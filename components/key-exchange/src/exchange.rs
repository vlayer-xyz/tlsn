//! This module implements the key exchange logic.

use async_trait::async_trait;
use mpz_common::{scoped, Context};
use mpz_garble::{value::ValueRef, Decode, Execute, Load, Memory};

use mpz_fields::{p256::P256, Field};
use mpz_share_conversion::ShareConvert;
use p256::{EncodedPoint, PublicKey, SecretKey};
use serio::{stream::IoStreamExt, SinkExt};
use std::fmt::Debug;

use crate::{
    circuit::build_pms_circuit,
    config::{KeyExchangeConfig, Role},
    error::ErrorKind,
    point_addition::derive_x_coord_share,
    KeyExchange, KeyExchangeError, Pms,
};

#[derive(Debug)]
enum State {
    Initialized,
    Setup {
        share_a0: ValueRef,
        share_b0: ValueRef,
        share_a1: ValueRef,
        share_b1: ValueRef,
        pms_0: ValueRef,
        pms_1: ValueRef,
        eq: ValueRef,
    },
    Complete,
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Error)
    }
}

/// An MPC key exchange protocol.
///
/// Can be either a leader or a follower depending on the `role` field in [`KeyExchangeConfig`].
#[derive(Debug)]
pub struct MpcKeyExchange<Ctx, C, E> {
    ctx: Ctx,
    /// Share conversion protocol 0.
    converter_0: C,
    /// Share conversion protocol 1.
    converter_1: C,
    /// MPC executor.
    executor: E,
    /// The private key of the party behind this instance, either follower or leader.
    private_key: Option<SecretKey>,
    /// The public key of the server.
    server_key: Option<PublicKey>,
    /// The config used for the key exchange protocol.
    config: KeyExchangeConfig,
    /// The state of the protocol.
    state: State,
}

impl<Ctx, C, E> MpcKeyExchange<Ctx, C, E> {
    /// Creates a new [`MpcKeyExchange`].
    ///
    /// # Arguments
    ///
    /// * `config` - Key exchange configuration.
    /// * `ctx` - Thread context.
    /// * `converter_0` - Share conversion protocol instance 0.
    /// * `converter_0` - Share conversion protocol instance 1.
    /// * `executor` - MPC executor.
    pub fn new(
        config: KeyExchangeConfig,
        ctx: Ctx,
        converter_0: C,
        converter_1: C,
        executor: E,
    ) -> Self {
        Self {
            ctx,
            converter_0,
            converter_1,
            executor,
            private_key: None,
            server_key: None,
            config,
            state: State::Initialized,
        }
    }
}

#[async_trait]
impl<Ctx, C, E> KeyExchange for MpcKeyExchange<Ctx, C, E>
where
    Ctx: Context,
    E: Execute + Load + Memory + Decode + Send,
    C: ShareConvert<Ctx, P256> + Send,
{
    fn server_key(&self) -> Option<PublicKey> {
        self.server_key
    }

    fn set_server_key(&mut self, server_key: PublicKey) {
        self.server_key = Some(server_key);
    }

    async fn setup(&mut self) -> Result<Pms, KeyExchangeError> {
        let State::Initialized = self.state.take() else {
            return Err(KeyExchangeError::state("not in initialized state"));
        };

        let (share_a0, share_b0, share_a1, share_b1) = match self.config.role() {
            Role::Leader => {
                let share_a0 = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_a0")?;
                let share_b0 = self.executor.new_blind_input::<[u8; 32]>("pms/share_b0")?;
                let share_a1 = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_a1")?;
                let share_b1 = self.executor.new_blind_input::<[u8; 32]>("pms/share_b1")?;

                (share_a0, share_b0, share_a1, share_b1)
            }
            Role::Follower => {
                let share_a0 = self.executor.new_blind_input::<[u8; 32]>("pms/share_a0")?;
                let share_b0 = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_b0")?;
                let share_a1 = self.executor.new_blind_input::<[u8; 32]>("pms/share_a1")?;
                let share_b1 = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_b1")?;

                (share_a0, share_b0, share_a1, share_b1)
            }
        };

        let pms_0 = self.executor.new_output::<[u8; 32]>("pms_0")?;
        let pms_1 = self.executor.new_output::<[u8; 32]>("pms_1")?;
        let eq = self.executor.new_output::<[u8; 32]>("eq")?;

        self.executor
            .load(
                build_pms_circuit(),
                &[
                    share_a0.clone(),
                    share_b0.clone(),
                    share_a1.clone(),
                    share_b1.clone(),
                ],
                &[pms_0.clone(), pms_1.clone(), eq.clone()],
            )
            .await?;

        self.state = State::Setup {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            pms_0: pms_0.clone(),
            pms_1,
            eq,
        };

        Ok(Pms::new(pms_0))
    }

    /// Compute the client's public key.
    ///
    /// The client's public key in this context is the combined public key (EC point addition) of
    /// the leader's public key and the follower's public key.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(self, private_key), ret, err)
    )]
    async fn compute_client_key(
        &mut self,
        private_key: SecretKey,
    ) -> Result<Option<PublicKey>, KeyExchangeError> {
        let public_key = private_key.public_key();
        self.private_key = Some(private_key);

        match self.config.role() {
            Role::Leader => {
                // Receive public key from follower.
                let follower_public_key: PublicKey = self.ctx.io_mut().expect_next().await?;

                // Combine public keys.
                let client_public_key = PublicKey::from_affine(
                    (public_key.to_projective() + follower_public_key.to_projective()).to_affine(),
                )?;

                Ok(Some(client_public_key))
            }
            Role::Follower => {
                // Send public key to leader.
                self.ctx.io_mut().send(public_key).await?;

                Ok(None)
            }
        }
    }

    /// Computes the PMS.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip_all, err)
    )]
    async fn compute_pms(&mut self) -> Result<Pms, KeyExchangeError> {
        let State::Setup {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            pms_0,
            pms_1,
            eq,
        } = self.state.take()
        else {
            return Err(KeyExchangeError::state("not in setup state"));
        };

        let server_key = match self.config.role() {
            Role::Leader => {
                // Send server public key to follower.
                if let Some(server_key) = &self.server_key {
                    self.ctx.io_mut().send(*server_key).await?;

                    *server_key
                } else {
                    return Err(KeyExchangeError::state("server public key not set"));
                }
            }
            Role::Follower => {
                let server_key = self.ctx.io_mut().expect_next().await?;

                self.server_key = Some(server_key);

                server_key
            }
        };

        let private_key = self
            .private_key
            .take()
            .ok_or(KeyExchangeError::state("private key not set"))?;

        let (pms_share_0, pms_share_1) = compute_pms_shares(
            &mut self.ctx,
            *self.config.role(),
            &mut self.converter_0,
            &mut self.converter_1,
            server_key,
            private_key,
        )
        .await?;

        let pms_share_0_bytes: [u8; 32] = pms_share_0
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");
        let pms_share_1_bytes: [u8; 32] = pms_share_1
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");

        match self.config.role() {
            Role::Leader => {
                self.executor.assign(&share_a0, pms_share_0_bytes)?;
                self.executor.assign(&share_a1, pms_share_1_bytes)?;
            }
            Role::Follower => {
                self.executor.assign(&share_b0, pms_share_0_bytes)?;
                self.executor.assign(&share_b1, pms_share_1_bytes)?;
            }
        }

        self.executor
            .execute(
                build_pms_circuit(),
                &[share_a0, share_b0, share_a1, share_b1],
                &[pms_0.clone(), pms_1, eq.clone()],
            )
            .await?;

        let eq: [u8; 32] = self
            .executor
            .decode(&[eq])
            .await?
            .pop()
            .expect("output 0 is eq")
            .try_into()
            .expect("eq is 32 bytes");

        if eq != [0u8; 32] {
            return Err(KeyExchangeError::new(
                ErrorKind::ShareConversion,
                "PMS values not equal",
            ));
        }

        self.state = State::Complete;

        Ok(Pms::new(pms_0))
    }
}

async fn compute_pms_shares<Ctx: Context, C: ShareConvert<Ctx, P256> + Send>(
    ctx: &mut Ctx,
    role: Role,
    converter_0: &mut C,
    converter_1: &mut C,
    server_key: PublicKey,
    private_key: SecretKey,
) -> Result<(P256, P256), KeyExchangeError> {
    // Compute the leader's/follower's share of the pre-master secret.
    //
    // We need to mimic the [diffie-hellman](p256::ecdh::diffie_hellman) function without the
    // [SharedSecret](p256::ecdh::SharedSecret) wrapper, because this makes it harder to get
    // the result as an EC curve point.
    let shared_secret = {
        let public_projective = server_key.to_projective();
        (public_projective * private_key.to_nonzero_scalar().as_ref()).to_affine()
    };

    let encoded_point = EncodedPoint::from(PublicKey::from_affine(shared_secret)?);

    let (pms_share_0, pms_share_1) = ctx
        .try_join(
            scoped!(|ctx| derive_x_coord_share(role, ctx, converter_0, encoded_point).await),
            scoped!(|ctx| derive_x_coord_share(role, ctx, converter_1, encoded_point).await),
        )
        .await??;

    Ok((pms_share_0, pms_share_1))
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_common::executor::{test_st_executor, STExecutor};
    use mpz_garble::protocol::deap::mock::{create_mock_deap_vm, MockFollower, MockLeader};
    use mpz_share_conversion::ideal::{ideal_share_converter, IdealShareConverter};
    use p256::{NonZeroScalar, PublicKey, SecretKey};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use serio::channel::MemoryDuplex;

    fn create_pair() -> (
        MpcKeyExchange<STExecutor<MemoryDuplex>, IdealShareConverter, MockLeader>,
        MpcKeyExchange<STExecutor<MemoryDuplex>, IdealShareConverter, MockFollower>,
    ) {
        let (leader_ctx, follower_ctx) = test_st_executor(8);
        let (leader_converter_0, follower_converter_0) = ideal_share_converter();
        let (follower_converter_1, leader_converter_1) = ideal_share_converter();
        let (leader_vm, follower_vm) = create_mock_deap_vm();

        let leader = MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(Role::Leader)
                .build()
                .unwrap(),
            leader_ctx,
            leader_converter_0,
            leader_converter_1,
            leader_vm,
        );

        let follower = MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(Role::Follower)
                .build()
                .unwrap(),
            follower_ctx,
            follower_converter_0,
            follower_converter_1,
            follower_vm,
        );

        (leader, follower)
    }

    #[tokio::test]
    async fn test_key_exchange() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&NonZeroScalar::random(&mut rng));

        let (mut leader, mut follower) = create_pair();

        tokio::try_join!(leader.setup(), follower.setup()).unwrap();

        let (client_public_key, _) = tokio::try_join!(
            leader.compute_client_key(leader_private_key.clone()),
            follower.compute_client_key(follower_private_key.clone())
        )
        .unwrap();

        leader.set_server_key(server_public_key);

        let client_public_key = client_public_key.unwrap();

        let expected_client_public_key = PublicKey::from_affine(
            (leader_private_key.public_key().to_projective()
                + follower_private_key.public_key().to_projective())
            .to_affine(),
        )
        .unwrap();

        assert_eq!(client_public_key, expected_client_public_key);
    }

    #[tokio::test]
    async fn test_compute_pms_shares() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);
        let (mut ctx_leader, mut ctx_follower) = test_st_executor(8);
        let (mut leader_converter_0, mut follower_converter_0) = ideal_share_converter();
        let (mut follower_converter_1, mut leader_converter_1) = ideal_share_converter();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let client_public_key = PublicKey::from_affine(
            (leader_private_key.public_key().to_projective()
                + follower_private_key.public_key().to_projective())
            .to_affine(),
        )
        .unwrap();

        let ((leader_share_0, leader_share_1), (follower_share_0, follower_share_1)) =
            tokio::try_join!(
                compute_pms_shares(
                    &mut ctx_leader,
                    Role::Leader,
                    &mut leader_converter_0,
                    &mut leader_converter_1,
                    server_public_key,
                    leader_private_key
                ),
                compute_pms_shares(
                    &mut ctx_follower,
                    Role::Follower,
                    &mut follower_converter_0,
                    &mut follower_converter_1,
                    server_public_key,
                    follower_private_key
                )
            )
            .unwrap();

        let expected_ecdh_x =
            p256::ecdh::diffie_hellman(server_private_key, client_public_key.as_affine());

        assert_eq!(
            (leader_share_0 + follower_share_0).to_be_bytes(),
            expected_ecdh_x.raw_secret_bytes().to_vec()
        );
        assert_eq!(
            (leader_share_1 + follower_share_1).to_be_bytes(),
            expected_ecdh_x.raw_secret_bytes().to_vec()
        );

        assert_ne!(leader_share_0, follower_share_0);
        assert_ne!(leader_share_1, follower_share_1);
    }

    #[tokio::test]
    async fn test_compute_pms() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (mut leader, mut follower) = create_pair();

        tokio::try_join!(leader.setup(), follower.setup()).unwrap();

        tokio::try_join!(
            leader.compute_client_key(leader_private_key),
            follower.compute_client_key(follower_private_key)
        )
        .unwrap();

        leader.set_server_key(server_public_key);

        let (_leader_pms, _follower_pms) =
            tokio::try_join!(leader.compute_pms(), follower.compute_pms()).unwrap();

        assert_eq!(leader.server_key.unwrap(), server_public_key);
        assert_eq!(follower.server_key.unwrap(), server_public_key);
    }
}
