//! This module provides an implementation of 2PC AES-GCM.

mod config;
#[cfg(feature = "mock")]
pub mod mock;
mod tag;

pub use config::{AesGcmConfig, AesGcmConfigBuilder, AesGcmConfigBuilderError, Role};

use crate::{
    msg::{AeadMessage, TagShare},
    Aead, AeadError,
};

use async_trait::async_trait;

use block_cipher::{Aes128, BlockCipher};
use futures::TryFutureExt;
use mpz_common::Context;
use mpz_core::commit::HashCommit;
use mpz_garble::value::ValueRef;
use serio::{SinkExt, StreamExt};
use tlsn_stream_cipher::{Aes128Ctr, StreamCipher};
use tlsn_universal_hash::UniversalHash;
use utils_aio::expect_msg_or_err;

pub(crate) use tag::AesGcmTagShare;
use tag::{build_ghash_data, AES_GCM_TAG_LEN};

/// An implementation of 2PC AES-GCM.
pub struct MpcAesGcm<Ctx> {
    config: AesGcmConfig,
    context: Ctx,
    aes_block: Box<dyn BlockCipher<Aes128>>,
    aes_ctr: Box<dyn StreamCipher<Aes128Ctr>>,
    ghash: Box<dyn UniversalHash>,
}

impl<Ctx> std::fmt::Debug for MpcAesGcm<Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAesGcm")
            .field("config", &self.config)
            .field("context", &"Context {{ ... }}")
            .field("aes_block", &"BlockCipher {{ ... }}")
            .field("aes_ctr", &"StreamCipher {{ ... }}")
            .field("ghash", &"UniversalHash {{ ... }}")
            .finish()
    }
}

impl<Ctx: Context> MpcAesGcm<Ctx> {
    /// Creates a new instance of [`MpcAesGcm`].
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(context, aes_block, aes_ctr, ghash), ret)
    )]
    pub fn new(
        config: AesGcmConfig,
        context: Ctx,
        aes_block: Box<dyn BlockCipher<Aes128>>,
        aes_ctr: Box<dyn StreamCipher<Aes128Ctr>>,
        ghash: Box<dyn UniversalHash>,
    ) -> Self {
        Self {
            config,
            context,
            aes_block,
            aes_ctr,
            ghash,
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err))]
    async fn compute_j0_share(&mut self, explicit_nonce: Vec<u8>) -> Result<Vec<u8>, AeadError> {
        let j0_share = self
            .aes_ctr
            .share_keystream_block(explicit_nonce.clone(), 1)
            .await?;

        Ok(j0_share)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn compute_tag_share(
        &mut self,
        explicit_nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<AesGcmTagShare, AeadError> {
        let j0_share = self.compute_j0_share(explicit_nonce.clone()).await?;

        let hash = self
            .ghash
            .finalize(build_ghash_data(aad, ciphertext))
            .await?;

        let mut tag_share = [0u8; 16];
        tag_share.copy_from_slice(&hash[..]);
        for i in 0..16 {
            tag_share[i] ^= j0_share[i];
        }

        Ok(AesGcmTagShare(tag_share))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err, ret))]
    async fn compute_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let tag_share = self
            .compute_tag_share(explicit_nonce, aad, ciphertext.clone())
            .await?;

        let channel = self.context.io_mut();
        let tag = match self.config.role() {
            Role::Leader => {
                // Send commitment of tag share to follower.
                let (tag_share_decommitment, tag_share_commitment) =
                    TagShare::from(tag_share).hash_commit();

                channel
                    .send(AeadMessage::TagShareCommitment(tag_share_commitment))
                    .await?;

                let msg = expect_msg_or_err!(channel, AeadMessage::TagShare)?;

                let other_tag_share = AesGcmTagShare::from_unchecked(&msg.share)?;

                // Send decommitment (tag share) to follower.
                channel
                    .send(AeadMessage::TagShareDecommitment(tag_share_decommitment))
                    .await?;

                tag_share + other_tag_share
            }
            Role::Follower => {
                // Wait for commitment from leader.
                let commitment = expect_msg_or_err!(channel, AeadMessage::TagShareCommitment)?;

                // Send tag share to leader.
                channel
                    .send(AeadMessage::TagShare(tag_share.into()))
                    .await?;

                // Expect decommitment (tag share) from leader.
                let decommitment = expect_msg_or_err!(channel, AeadMessage::TagShareDecommitment)?;

                // Verify decommitment.
                decommitment.verify(&commitment).map_err(|_| {
                    AeadError::ValidationError(
                        "Leader tag share commitment verification failed".to_string(),
                    )
                })?;

                let other_tag_share =
                    AesGcmTagShare::from_unchecked(&decommitment.into_inner().share)?;

                tag_share + other_tag_share
            }
        };

        Ok(tag)
    }

    /// Splits off the tag from the end of the payload and verifies it.
    async fn _verify_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        payload: &mut Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AeadError> {
        let purported_tag = payload.split_off(payload.len() - AES_GCM_TAG_LEN);

        let tag = self
            .compute_tag(explicit_nonce, payload.clone(), aad)
            .await?;

        // Reject if tag is incorrect.
        if tag != purported_tag {
            return Err(AeadError::CorruptedTag);
        }

        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> Aead for MpcAesGcm<Ctx> {
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", err))]
    async fn set_key(&mut self, key: ValueRef, iv: ValueRef) -> Result<(), AeadError> {
        self.aes_block.set_key(key.clone());
        self.aes_ctr.set_key(key, iv);

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", err))]
    async fn decode_key_private(&mut self) -> Result<(), AeadError> {
        self.aes_ctr
            .decode_key_private()
            .await
            .map_err(AeadError::from)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", err))]
    async fn decode_key_blind(&mut self) -> Result<(), AeadError> {
        self.aes_ctr
            .decode_key_blind()
            .await
            .map_err(AeadError::from)
    }

    fn set_transcript_id(&mut self, id: &str) {
        self.aes_ctr.set_transcript_id(id)
    }

    async fn preprocess(&mut self, len: usize) -> Result<(), AeadError> {
        self.aes_ctr.preprocess(len).await.map_err(AeadError::from)
    }

    async fn setup(&mut self) -> Result<(), AeadError> {
        // Share zero block.
        let h_share = self.aes_block.encrypt_share(vec![0u8; 16]).await?;
        self.ghash.set_key(h_share).await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(plaintext), err)
    )]
    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_public(explicit_nonce.clone(), plaintext)
            .await?;

        let tag = self
            .compute_tag(explicit_nonce, ciphertext.clone(), aad)
            .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(plaintext), err)
    )]
    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_private(explicit_nonce.clone(), plaintext)
            .await?;

        let tag = self
            .compute_tag(explicit_nonce, ciphertext.clone(), aad)
            .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", err))]
    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext_len: usize,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        let ciphertext = self
            .aes_ctr
            .encrypt_blind(explicit_nonce.clone(), plaintext_len)
            .await?;

        let tag = self
            .compute_tag(explicit_nonce, ciphertext.clone(), aad)
            .await?;

        let mut payload = ciphertext;
        payload.extend(tag);

        Ok(payload)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(payload), err)
    )]
    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        self._verify_tag(explicit_nonce.clone(), &mut payload, aad)
            .await?;

        self.aes_ctr
            .decrypt_public(explicit_nonce, payload)
            .map_err(AeadError::from)
            .await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(payload), err)
    )]
    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        self._verify_tag(explicit_nonce.clone(), &mut payload, aad)
            .await?;

        self.aes_ctr
            .decrypt_private(explicit_nonce, payload)
            .map_err(AeadError::from)
            .await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(payload), err)
    )]
    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AeadError> {
        self._verify_tag(explicit_nonce.clone(), &mut payload, aad)
            .await?;

        self.aes_ctr
            .decrypt_blind(explicit_nonce, payload)
            .map_err(AeadError::from)
            .await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(payload), err)
    )]
    async fn verify_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AeadError> {
        self._verify_tag(explicit_nonce.clone(), &mut payload, aad)
            .await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(payload), err)
    )]
    async fn prove_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        self._verify_tag(explicit_nonce.clone(), &mut payload, aad)
            .await?;

        self.prove_plaintext_no_tag(explicit_nonce, payload).await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(ciphertext), err)
    )]
    async fn prove_plaintext_no_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError> {
        self.aes_ctr
            .prove_plaintext(explicit_nonce, ciphertext)
            .map_err(AeadError::from)
            .await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(payload), err)
    )]
    async fn verify_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut payload: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<(), AeadError> {
        self._verify_tag(explicit_nonce.clone(), &mut payload, aad)
            .await?;

        self.verify_plaintext_no_tag(explicit_nonce, payload).await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(ciphertext), err)
    )]
    async fn verify_plaintext_no_tag(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<(), AeadError> {
        self.aes_ctr
            .verify_plaintext(explicit_nonce, ciphertext)
            .map_err(AeadError::from)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aes_gcm::{mock::create_mock_aes_gcm_pair, AesGcmConfigBuilder, MpcAesGcm, Role},
        Aead, AeadError,
    };
    use ::aes_gcm::{
        aead::{AeadInPlace, KeyInit},
        Aes128Gcm, Nonce,
    };
    use mpz_common::executor::STExecutor;
    use mpz_garble::{protocol::deap::mock::create_mock_deap_vm, Memory};
    use serio::channel::MemoryDuplex;

    fn reference_impl(
        key: &[u8],
        iv: &[u8],
        explicit_nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let cipher = Aes128Gcm::new_from_slice(key).unwrap();
        let nonce = [iv, explicit_nonce].concat();
        let nonce = Nonce::from_slice(nonce.as_slice());

        let mut ciphertext = plaintext.to_vec();
        cipher
            .encrypt_in_place(nonce, aad, &mut ciphertext)
            .unwrap();

        ciphertext
    }

    async fn setup_pair(
        key: Vec<u8>,
        iv: Vec<u8>,
    ) -> (
        MpcAesGcm<STExecutor<MemoryDuplex>>,
        MpcAesGcm<STExecutor<MemoryDuplex>>,
    ) {
        let (leader_vm, follower_vm) = create_mock_deap_vm();

        let leader_key = leader_vm
            .new_public_array_input::<u8>("key", key.len())
            .unwrap();
        let leader_iv = leader_vm
            .new_public_array_input::<u8>("iv", iv.len())
            .unwrap();

        leader_vm.assign(&leader_key, key.clone()).unwrap();
        leader_vm.assign(&leader_iv, iv.clone()).unwrap();

        let follower_key = follower_vm
            .new_public_array_input::<u8>("key", key.len())
            .unwrap();
        let follower_iv = follower_vm
            .new_public_array_input::<u8>("iv", iv.len())
            .unwrap();

        follower_vm.assign(&follower_key, key.clone()).unwrap();
        follower_vm.assign(&follower_iv, iv.clone()).unwrap();

        let leader_config = AesGcmConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Leader)
            .build()
            .unwrap();
        let follower_config = AesGcmConfigBuilder::default()
            .id("test".to_string())
            .role(Role::Follower)
            .build()
            .unwrap();

        let (mut leader, mut follower) = create_mock_aes_gcm_pair(
            "test",
            (leader_vm, follower_vm),
            leader_config,
            follower_config,
        )
        .await;

        futures::try_join!(
            leader.set_key(leader_key, leader_iv),
            follower.set_key(follower_key, follower_iv)
        )
        .unwrap();

        futures::try_join!(leader.setup(), follower.setup()).unwrap();

        (leader, follower)
    }

    #[tokio::test]
    async fn test_aes_gcm_encrypt_private() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_ciphertext, follower_ciphertext) = tokio::try_join!(
            leader.encrypt_private(explicit_nonce.clone(), plaintext.clone(), aad.clone(),),
            follower.encrypt_blind(explicit_nonce.clone(), plaintext.len(), aad.clone())
        )
        .unwrap();

        assert_eq!(leader_ciphertext, follower_ciphertext);
        assert_eq!(
            leader_ciphertext,
            reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad)
        );
    }

    #[tokio::test]
    async fn test_aes_gcm_encrypt_public() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_ciphertext, follower_ciphertext) = tokio::try_join!(
            leader.encrypt_public(explicit_nonce.clone(), plaintext.clone(), aad.clone(),),
            follower.encrypt_public(explicit_nonce.clone(), plaintext.clone(), aad.clone(),)
        )
        .unwrap();

        assert_eq!(leader_ciphertext, follower_ciphertext);
        assert_eq!(
            leader_ciphertext,
            reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad)
        );
    }

    #[tokio::test]
    async fn test_aes_gcm_decrypt_private() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_plaintext, _) = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), ciphertext, aad.clone(),)
        )
        .unwrap();

        assert_eq!(leader_plaintext, plaintext);
    }

    #[tokio::test]
    async fn test_aes_gcm_decrypt_private_bad_tag() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let len = ciphertext.len();

        // corrupt tag
        let mut corrupted = ciphertext.clone();
        corrupted[len - 1] -= 1;

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // leader receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), corrupted.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // follower receives corrupted tag
        let err = tokio::try_join!(
            leader.decrypt_private(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_blind(explicit_nonce.clone(), corrupted.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));
    }

    #[tokio::test]
    async fn test_aes_gcm_decrypt_public() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        let (leader_plaintext, follower_plaintext) = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), ciphertext, aad.clone(),)
        )
        .unwrap();

        assert_eq!(leader_plaintext, plaintext);
        assert_eq!(leader_plaintext, follower_plaintext);
    }

    #[tokio::test]
    async fn test_aes_gcm_decrypt_public_bad_tag() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let len = ciphertext.len();

        // Corrupt tag.
        let mut corrupted = ciphertext.clone();
        corrupted[len - 1] -= 1;

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // Leader receives corrupted tag.
        let err = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), corrupted.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        // Follower receives corrupted tag.
        let err = tokio::try_join!(
            leader.decrypt_public(explicit_nonce.clone(), ciphertext.clone(), aad.clone(),),
            follower.decrypt_public(explicit_nonce.clone(), corrupted.clone(), aad.clone(),)
        )
        .unwrap_err();
        assert!(matches!(err, AeadError::CorruptedTag));
    }

    #[tokio::test]
    async fn test_aes_gcm_verify_tag() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let explicit_nonce = vec![0u8; 8];
        let plaintext = vec![1u8; 32];
        let aad = vec![2u8; 12];
        let ciphertext = reference_impl(&key, &iv, &explicit_nonce, &plaintext, &aad);

        let len = ciphertext.len();

        let (mut leader, mut follower) = setup_pair(key.clone(), iv.clone()).await;

        tokio::try_join!(
            leader.verify_tag(explicit_nonce.clone(), ciphertext.clone(), aad.clone()),
            follower.verify_tag(explicit_nonce.clone(), ciphertext.clone(), aad.clone())
        )
        .unwrap();

        //Corrupt tag.
        let mut corrupted = ciphertext.clone();
        corrupted[len - 1] -= 1;

        let (leader_res, follower_res) = tokio::join!(
            leader.verify_tag(explicit_nonce.clone(), corrupted.clone(), aad.clone()),
            follower.verify_tag(explicit_nonce.clone(), corrupted, aad.clone())
        );

        assert!(matches!(leader_res.unwrap_err(), AeadError::CorruptedTag));
        assert!(matches!(follower_res.unwrap_err(), AeadError::CorruptedTag));
    }
}
