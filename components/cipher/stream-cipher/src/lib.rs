//! This crate provides a 2PC stream cipher implementation using a block cipher in counter mode.
//!
//! Each party plays a specific role, either the `StreamCipherLeader` or the `StreamCipherFollower`.
//! Both parties work together to encrypt and decrypt messages using a shared key.
//!
//! # Transcript
//!
//! Using the `record` flag, the `StreamCipherFollower` can optionally use a dedicated stream when
//! encoding the plaintext labels, which allows the `StreamCipherLeader` to build a transcript of
//! active labels which are pushed to the provided `TranscriptSink`.
//!
//! Afterwards, the `StreamCipherLeader` can create commitments to the transcript which can be used in
//! a selective disclosure protocol.

// TODO: Uncomment here
// #![deny(missing_docs, unreachable_pub, unused_must_use)]
// #![deny(clippy::all)]
// #![deny(unsafe_code)]

mod cipher;
mod circuit;
mod config;
pub(crate) mod error;
pub mod keystream;
mod mode;
pub mod stream_cipher;

pub use self::cipher::{Aes128Ctr, CtrCircuit};
use async_trait::async_trait;
pub use config::{StreamCipherConfig, StreamCipherConfigBuilder, StreamCipherConfigBuilderError};
pub use error::StreamCipherError;
use keystream::KeyStreamRefs;
pub use mode::{Blind, Mode, Private, Public, Shared, TextRefs};
use mpz_circuits::types::Value;
use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Thread};
pub use stream_cipher::MpcStreamCipher;
use utils::id::NestedId;

/// A trait for MPC stream ciphers.
#[async_trait]
pub trait StreamCipher<C>: Send + Sync {
    /// Applies the keystream to the given plaintext, where all parties
    /// provide the plaintext as an input.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to apply the keystream to.
    /// * `keystream_refs` - References to input and output variables of the keystream.
    async fn encrypt<M: Mode + Send>(
        &mut self,
        plaintext: TextRefs<M>,
        keystream: KeyStreamRefs<C>,
    ) -> Result<M::Output, StreamCipherError>;

    /// Applies the keystream to the given plaintext without revealing it
    /// to the other party(s).
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to apply the keystream to.
    /// * `keystream_refs` - References to input and output variables of the keystream.
    async fn decrypt<M: Mode + Send>(
        &mut self,
        ciphertext: TextRefs<M>,
        keystream: KeyStreamRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError>;
}

/// Zk Proving for knowledge of plaintext which encrypts to a ciphertext.
#[async_trait]
pub trait ZkProve<C>: Send + Sync {
    /// Locally decrypts the provided ciphertext and then proves in ZK to the other party(s) that the
    /// plaintext is correct.
    ///
    /// Returns the plaintext.
    ///
    /// This method requires this party to know the encryption key, which can be achieved by calling
    /// the `decode_key_private` method.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt and prove.
    /// * `cipher_refs` - References to input and output variables of the cipher.
    async fn prove_plaintext(
        &mut self,
        ciphertext: Vec<u8>,
        cipher_refs: KeyStreamRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError>;

    /// Verifies the other party(s) can prove they know a plaintext which encrypts to the given ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to verify.
    /// * `cipher_refs` - References to input and output variables of the cipher.
    async fn verify_plaintext(
        &mut self,
        ciphertext: Vec<u8>,
        cipher_refs: KeyStreamRefs<C>,
    ) -> Result<(), StreamCipherError>;
}

// TODO: This is a temporary location.
/// A subset of plaintext bytes processed by the stream cipher.
///
/// Note that `Transcript` does not store the actual bytes. Instead, it provides IDs which are
/// assigned to plaintext bytes of the stream cipher.
pub struct Transcript {
    /// The ID of this transcript.
    id: String,
    /// The ID for the next plaintext byte.
    plaintext: NestedId,
}

impl Transcript {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            plaintext: NestedId::new(id).append_counter(),
        }
    }

    /// Returns unique identifiers for the next plaintext bytes in the transcript.
    pub fn extend_plaintext(&mut self, len: usize) -> Vec<String> {
        (0..len)
            .map(|_| self.plaintext.increment_in_place().to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::cipher::Aes128Ctr;

    use super::*;

    use mpz_garble::{
        protocol::deap::mock::{create_mock_deap_vm, MockFollower, MockLeader},
        Memory,
    };
    use rstest::*;

    async fn create_test_pair<C: CtrCircuit>(
        start_ctr: usize,
        key: [u8; 16],
        iv: [u8; 4],
    ) -> (
        MpcStreamCipher<C, MockLeader>,
        MpcStreamCipher<C, MockFollower>,
    ) {
        let (leader_vm, follower_vm) = create_mock_deap_vm();

        let leader_key = leader_vm.new_public_input::<[u8; 16]>("key").unwrap();
        let leader_iv = leader_vm.new_public_input::<[u8; 4]>("iv").unwrap();

        leader_vm.assign(&leader_key, key).unwrap();
        leader_vm.assign(&leader_iv, iv).unwrap();

        let follower_key = follower_vm.new_public_input::<[u8; 16]>("key").unwrap();
        let follower_iv = follower_vm.new_public_input::<[u8; 4]>("iv").unwrap();

        follower_vm.assign(&follower_key, key).unwrap();
        follower_vm.assign(&follower_iv, iv).unwrap();

        let leader_config = StreamCipherConfig::builder()
            .id("test")
            .start_ctr(start_ctr)
            .build()
            .unwrap();

        let follower_config = StreamCipherConfig::builder()
            .id("test")
            .start_ctr(start_ctr)
            .build()
            .unwrap();

        let mut leader = MpcStreamCipher::<C, _>::new(leader_config, leader_vm);
        leader.set_key(leader_key, leader_iv);

        let mut follower = MpcStreamCipher::<C, _>::new(follower_config, follower_vm);
        follower.set_key(follower_key, follower_iv);

        (leader, follower)
    }

    #[rstest]
    #[timeout(Duration::from_millis(10000))]
    #[tokio::test]
    async fn test_stream_cipher_public() {
        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [0u8; 8];

        let msg = b"This is a test message which will be encrypted using AES-CTR.".to_vec();

        let (mut leader, mut follower) = create_test_pair::<Aes128Ctr>(1, key, iv).await;

        let leader_fut = async {
            let leader_encrypted_msg = leader
                .encrypt_public(explicit_nonce.to_vec(), msg.clone())
                .await
                .unwrap();

            let leader_decrypted_msg = leader
                .decrypt_public(explicit_nonce.to_vec(), leader_encrypted_msg.clone())
                .await
                .unwrap();

            (leader_encrypted_msg, leader_decrypted_msg)
        };

        let follower_fut = async {
            let follower_encrypted_msg = follower
                .encrypt_public(explicit_nonce.to_vec(), msg.clone())
                .await
                .unwrap();

            let follower_decrypted_msg = follower
                .decrypt_public(explicit_nonce.to_vec(), follower_encrypted_msg.clone())
                .await
                .unwrap();

            (follower_encrypted_msg, follower_decrypted_msg)
        };

        let (
            (leader_encrypted_msg, leader_decrypted_msg),
            (follower_encrypted_msg, follower_decrypted_msg),
        ) = futures::join!(leader_fut, follower_fut);

        let reference = Aes128Ctr::apply_keystream(&key, &iv, 1, &explicit_nonce, &msg).unwrap();

        assert_eq!(leader_encrypted_msg, reference);
        assert_eq!(leader_decrypted_msg, msg);
        assert_eq!(follower_encrypted_msg, reference);
        assert_eq!(follower_decrypted_msg, msg);
    }

    #[rstest]
    #[timeout(Duration::from_millis(10000))]
    #[tokio::test]
    async fn test_stream_cipher_private() {
        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [1u8; 8];

        let msg = b"This is a test message which will be encrypted using AES-CTR.".to_vec();

        let ciphertext = Aes128Ctr::apply_keystream(&key, &iv, 1, &explicit_nonce, &msg).unwrap();

        let (mut leader, mut follower) = create_test_pair::<Aes128Ctr>(1, key, iv).await;

        let leader_fut = async {
            let leader_decrypted_msg = leader
                .decrypt_private(explicit_nonce.to_vec(), ciphertext.clone())
                .await
                .unwrap();

            let leader_encrypted_msg = leader
                .encrypt_private(explicit_nonce.to_vec(), leader_decrypted_msg.clone())
                .await
                .unwrap();

            (leader_encrypted_msg, leader_decrypted_msg)
        };

        let follower_fut = async {
            follower
                .decrypt_blind(explicit_nonce.to_vec(), ciphertext.clone())
                .await
                .unwrap();

            follower
                .encrypt_blind(explicit_nonce.to_vec(), msg.len())
                .await
                .unwrap()
        };

        let ((leader_encrypted_msg, leader_decrypted_msg), follower_encrypted_msg) =
            futures::join!(leader_fut, follower_fut);

        assert_eq!(leader_encrypted_msg, ciphertext);
        assert_eq!(leader_decrypted_msg, msg);
        assert_eq!(follower_encrypted_msg, ciphertext);

        futures::try_join!(
            leader.thread_mut().finalize(),
            follower.thread_mut().finalize()
        )
        .unwrap();
    }

    #[rstest]
    #[timeout(Duration::from_millis(10000))]
    #[tokio::test]
    async fn test_stream_cipher_share_key_block() {
        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [0u8; 8];

        let (mut leader, mut follower) = create_test_pair::<Aes128Ctr>(1, key, iv).await;

        let leader_fut = async {
            leader
                .share_keystream_block(explicit_nonce.to_vec(), 1)
                .await
                .unwrap()
        };

        let follower_fut = async {
            follower
                .share_keystream_block(explicit_nonce.to_vec(), 1)
                .await
                .unwrap()
        };

        let (leader_share, follower_share) = futures::join!(leader_fut, follower_fut);

        let key_block = leader_share
            .into_iter()
            .zip(follower_share)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        let reference =
            Aes128Ctr::apply_keystream(&key, &iv, 1, &explicit_nonce, &[0u8; 16]).unwrap();

        assert_eq!(reference, key_block);
    }

    #[rstest]
    #[timeout(Duration::from_millis(10000))]
    #[tokio::test]
    async fn test_stream_cipher_zk() {
        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [1u8; 8];

        let msg = b"This is a test message which will be encrypted using AES-CTR.".to_vec();

        let ciphertext = Aes128Ctr::apply_keystream(&key, &iv, 2, &explicit_nonce, &msg).unwrap();

        let (mut leader, mut follower) = create_test_pair::<Aes128Ctr>(2, key, iv).await;

        futures::try_join!(leader.decode_key_private(), follower.decode_key_blind()).unwrap();

        futures::try_join!(
            leader.prove_plaintext(explicit_nonce.to_vec(), ciphertext.clone()),
            follower.verify_plaintext(explicit_nonce.to_vec(), ciphertext)
        )
        .unwrap();
        futures::try_join!(
            leader.thread_mut().finalize(),
            follower.thread_mut().finalize()
        )
        .unwrap();
    }

    #[rstest]
    #[case::one_block(16)]
    #[case::partial(17)]
    #[case::extra(128)]
    #[timeout(Duration::from_millis(10000))]
    #[tokio::test]
    async fn test_stream_cipher_preprocess(#[case] len: usize) {
        let key = [0u8; 16];
        let iv = [0u8; 4];
        let explicit_nonce = [1u8; 8];

        let msg = b"This is a test message which will be encrypted using AES-CTR.".to_vec();

        let ciphertext = Aes128Ctr::apply_keystream(&key, &iv, 1, &explicit_nonce, &msg).unwrap();

        let (mut leader, mut follower) = create_test_pair::<Aes128Ctr>(1, key, iv).await;

        let leader_fut = async {
            leader.preprocess(len).await.unwrap();

            leader
                .decrypt_private(explicit_nonce.to_vec(), ciphertext.clone())
                .await
                .unwrap()
        };

        let follower_fut = async {
            follower.preprocess(len).await.unwrap();

            follower
                .decrypt_blind(explicit_nonce.to_vec(), ciphertext.clone())
                .await
                .unwrap();
        };

        let (leader_decrypted_msg, _) = futures::join!(leader_fut, follower_fut);

        assert_eq!(leader_decrypted_msg, msg);

        futures::try_join!(
            leader.thread_mut().finalize(),
            follower.thread_mut().finalize()
        )
        .unwrap();
    }
}
