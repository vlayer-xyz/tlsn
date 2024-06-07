use aead::{
    aes_gcm::{AesGcmConfig, MpcAesGcm, Role as AesGcmRole},
    Aead,
};
use block_cipher::{Aes128, BlockCipherConfigBuilder, MpcBlockCipher};
use futures::StreamExt;
use hmac_sha256::{MpcPrf, Prf, PrfConfig, SessionKeys};
use key_exchange::{KeyExchange, KeyExchangeConfig, Role as KeyExchangeRole};
use mpz_common::executor::{test_mt_executor, STExecutor};
use mpz_core::{prg::Prg, Block};
use mpz_garble::{config::Role as GarbleRole, protocol::deap::mock::create_mock_deap_vm};
use mpz_garble::{config::Role, protocol::deap::DEAPThread};
use mpz_ot::{
    chou_orlandi::{
        Receiver as BaseReceiver, ReceiverConfig as BaseReceiverConfig, Sender as BaseSender,
        SenderConfig as BaseSenderConfig,
    },
    kos::{Receiver, ReceiverConfig, Sender, SenderConfig},
    OTSetup,
};
use p256::{NonZeroScalar, PublicKey, SecretKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tlsn_stream_cipher::{Aes128Ctr, MpcStreamCipher, StreamCipherConfig};
use tlsn_universal_hash::ghash::{Ghash, GhashConfig};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uid_mux::{yamux, UidYamux};
use utils_aio::{codec::BincodeMux, mux::MuxChannel};

const OT_SETUP_COUNT: usize = 50_000;

/// The following integration test checks the interplay of individual components of the TLSNotary
/// protocol. These are:
///   - channel multiplexing
///   - oblivious transfer
///   - point addition
///   - key exchange
///   - prf
///   - aead cipher (stream cipher + ghash)
#[tokio::test]
async fn test_components() {
    let mut rng = Prg::from_seed(Block::ZERO);

    let (exec_a, exec_b) = test_mt_executor(128);

    let leader_ot_sender_config = SenderConfig::default();
    let follower_ot_recvr_config = ReceiverConfig::default();

    let follower_ot_sender_config = SenderConfig::builder().sender_commit().build().unwrap();
    let leader_ot_recvr_config = ReceiverConfig::builder().sender_commit().build().unwrap();

    let mut leader_ot_sender = Sender::new(
        leader_ot_sender_config,
        BaseReceiver::new(BaseReceiverConfig::default()),
    );

    let mut leader_ot_recvr = Receiver::new(
        leader_ot_recvr_config,
        BaseSender::new(
            BaseSenderConfig::builder()
                .receiver_commit()
                .build()
                .unwrap(),
        ),
    );

    let mut follower_ot_sender = Sender::new(
        leader_ot_sender_config,
        BaseReceiver::new(
            BaseReceiverConfig::builder()
                .receiver_commit()
                .build()
                .unwrap(),
        ),
    );

    let mut follower_ot_recvr = Receiver::new(
        follower_ot_recvr_config,
        BaseSender::new(BaseSenderConfig::default()),
    );

    let ctx_a1 = exec_a.new_thread().await.unwrap();
    let ctx_a2 = exec_a.new_thread().await.unwrap();

    let ctx_b1 = exec_b.new_thread().await.unwrap();
    let ctx_b2 = exec_b.new_thread().await.unwrap();

    leader_ot_sender.setup(&mut ctx_a1).await.unwrap();
    leader_ot_recvr.setup(&mut ctx_a2).await.unwrap();

    follower_ot_sender.setup(&mut ctx_b1).await.unwrap();
    follower_ot_recvr.setup(&mut ctx_b2).await.unwrap();

    let ctx_a = exec_a.new_thread().await.unwrap();
    let ctx_b = exec_b.new_thread().await.unwrap();

    let mut deap_leader = DEAPThread::new(
        Role::Leader,
        [0u8; 32],
        ctx_a,
        leader_ot_sender,
        leader_ot_recvr,
    );

    let mut deap_follower = DEAPThread::new(
        Role::Follower,
        [1u8; 32],
        ctx_b,
        follower_ot_sender,
        follower_ot_recvr,
    );

    let leader_p256_sender = ff::ConverterSender::<P256, _>::new(
        ff::SenderConfig::builder().id("p256/0").build().unwrap(),
        leader_ot_sender.clone(),
        leader_mux.get_channel("p256/0").await.unwrap(),
    );

    let leader_p256_receiver = ff::ConverterReceiver::<P256, _>::new(
        ff::ReceiverConfig::builder().id("p256/1").build().unwrap(),
        follower_ot_recvr.clone(),
        leader_mux.get_channel("p256/1").await.unwrap(),
    );

    let follower_p256_sender = ff::ConverterSender::<P256, _>::new(
        ff::SenderConfig::builder().id("p256/1").build().unwrap(),
        leader_ot_sender.clone(),
        follower_mux.get_channel("p256/1").await.unwrap(),
    );

    let follower_p256_receiver = ff::ConverterReceiver::<P256, _>::new(
        ff::ReceiverConfig::builder().id("p256/0").build().unwrap(),
        follower_ot_recvr.clone(),
        follower_mux.get_channel("p256/0").await.unwrap(),
    );

    let leader_pa_sender = MpcPointAddition::new(PointAdditionRole::Leader, leader_p256_sender);
    let leader_pa_receiver = MpcPointAddition::new(PointAdditionRole::Leader, leader_p256_receiver);

    let follower_pa_sender =
        MpcPointAddition::new(PointAdditionRole::Follower, follower_p256_sender);

    let follower_pa_receiver =
        MpcPointAddition::new(PointAdditionRole::Follower, follower_p256_receiver);

    let mut leader_ke = key_exchange::KeyExchangeCore::new(
        leader_mux.get_channel("ke").await.unwrap(),
        leader_pa_sender,
        leader_pa_receiver,
        leader_vm.new_thread("ke").await.unwrap(),
        KeyExchangeConfig::builder()
            .id("ke")
            .role(KeyExchangeRole::Leader)
            .build()
            .unwrap(),
    );

    let mut follower_ke = key_exchange::KeyExchangeCore::new(
        follower_mux.get_channel("ke").await.unwrap(),
        follower_pa_sender,
        follower_pa_receiver,
        follower_vm.new_thread("ke").await.unwrap(),
        KeyExchangeConfig::builder()
            .id("ke")
            .role(KeyExchangeRole::Follower)
            .build()
            .unwrap(),
    );

    let (leader_pms, follower_pms) =
        futures::try_join!(leader_ke.setup(), follower_ke.setup()).unwrap();

    let mut leader_prf = MpcPrf::new(
        PrfConfig::builder()
            .role(hmac_sha256::Role::Leader)
            .build()
            .unwrap(),
        leader_vm.new_thread("prf/0").await.unwrap(),
        leader_vm.new_thread("prf/1").await.unwrap(),
    );
    let mut follower_prf = MpcPrf::new(
        PrfConfig::builder()
            .role(hmac_sha256::Role::Follower)
            .build()
            .unwrap(),
        follower_vm.new_thread("prf/0").await.unwrap(),
        follower_vm.new_thread("prf/1").await.unwrap(),
    );

    futures::try_join!(
        leader_prf.setup(leader_pms.into_value()),
        follower_prf.setup(follower_pms.into_value())
    )
    .unwrap();

    let block_cipher_config = BlockCipherConfigBuilder::default()
        .id("aes")
        .build()
        .unwrap();
    let leader_block_cipher = MpcBlockCipher::<Aes128, _>::new(
        block_cipher_config.clone(),
        leader_vm.new_thread("block_cipher").await.unwrap(),
    );
    let follower_block_cipher = MpcBlockCipher::<Aes128, _>::new(
        block_cipher_config,
        follower_vm.new_thread("block_cipher").await.unwrap(),
    );

    let stream_cipher_config = StreamCipherConfig::builder()
        .id("aes-ctr")
        .transcript_id("tx")
        .build()
        .unwrap();
    let leader_stream_cipher = MpcStreamCipher::<Aes128Ctr, _>::new(
        stream_cipher_config.clone(),
        leader_vm.new_thread_pool("aes-ctr", 4).await.unwrap(),
    );
    let follower_stream_cipher = MpcStreamCipher::<Aes128Ctr, _>::new(
        stream_cipher_config,
        follower_vm.new_thread_pool("aes-ctr", 4).await.unwrap(),
    );

    let mut leader_gf2 = ff::ConverterSender::<Gf2_128, _>::new(
        ff::SenderConfig::builder()
            .id("gf2")
            .record()
            .build()
            .unwrap(),
        leader_ot_sender.clone(),
        leader_mux.get_channel("gf2").await.unwrap(),
    );

    let mut follower_gf2 = ff::ConverterReceiver::<Gf2_128, _>::new(
        ff::ReceiverConfig::builder()
            .id("gf2")
            .record()
            .build()
            .unwrap(),
        follower_ot_recvr.clone(),
        follower_mux.get_channel("gf2").await.unwrap(),
    );

    let ghash_config = GhashConfig::builder()
        .id("aes_gcm/ghash")
        .initial_block_count(64)
        .build()
        .unwrap();

    let leader_ghash = Ghash::new(ghash_config.clone(), leader_gf2.handle().unwrap());
    let follower_ghash = Ghash::new(ghash_config, follower_gf2.handle().unwrap());

    let mut leader_aead = MpcAesGcm::new(
        AesGcmConfig::builder()
            .id("aes_gcm")
            .role(AesGcmRole::Leader)
            .build()
            .unwrap(),
        leader_mux.get_channel("aes_gcm").await.unwrap(),
        Box::new(leader_block_cipher),
        Box::new(leader_stream_cipher),
        Box::new(leader_ghash),
    );

    let mut follower_aead = MpcAesGcm::new(
        AesGcmConfig::builder()
            .id("aes_gcm")
            .role(AesGcmRole::Follower)
            .build()
            .unwrap(),
        follower_mux.get_channel("aes_gcm").await.unwrap(),
        Box::new(follower_block_cipher),
        Box::new(follower_stream_cipher),
        Box::new(follower_ghash),
    );

    let leader_private_key = SecretKey::random(&mut rng);
    let follower_private_key = SecretKey::random(&mut rng);
    let server_public_key = PublicKey::from_secret_scalar(&NonZeroScalar::random(&mut rng));

    // Setup complete.

    let _ = tokio::try_join!(
        leader_ke.compute_client_key(leader_private_key),
        follower_ke.compute_client_key(follower_private_key)
    )
    .unwrap();

    leader_ke.set_server_key(server_public_key);

    tokio::try_join!(leader_ke.compute_pms(), follower_ke.compute_pms()).unwrap();

    let (leader_session_keys, follower_session_keys) = tokio::try_join!(
        leader_prf.compute_session_keys_private([0u8; 32], [0u8; 32]),
        follower_prf.compute_session_keys_blind()
    )
    .unwrap();

    let SessionKeys {
        client_write_key: leader_key,
        client_iv: leader_iv,
        ..
    } = leader_session_keys;

    let SessionKeys {
        client_write_key: follower_key,
        client_iv: follower_iv,
        ..
    } = follower_session_keys;

    tokio::try_join!(
        leader_aead.set_key(leader_key, leader_iv),
        follower_aead.set_key(follower_key, follower_iv)
    )
    .unwrap();

    tokio::try_join!(leader_aead.setup(), follower_aead.setup()).unwrap();

    let msg = vec![0u8; 4096];

    let _ = tokio::try_join!(
        leader_aead.encrypt_private(vec![0u8; 8], msg.clone(), vec![]),
        follower_aead.encrypt_blind(vec![0u8; 8], msg.len(), vec![])
    )
    .unwrap();

    follower_ot_sender.shutdown().await.unwrap();

    tokio::try_join!(leader_vm.finalize(), follower_vm.finalize()).unwrap();
    tokio::try_join!(leader_gf2.reveal(), follower_gf2.verify()).unwrap();
}
