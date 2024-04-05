use mpz_ot::{chou_orlandi, kos};
use mpz_share_conversion::{ReceiverConfig, SenderConfig};
use tls_client::RootCertStore;
use tls_mpc::{MpcTlsCommonConfig, MpcTlsLeaderConfig};
use tlsn_core::hash::HashAlgorithm;

const DEFAULT_MAX_TRANSCRIPT_SIZE: usize = 1 << 14; // 16Kb

/// Configuration for the prover
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct ProverConfig {
    /// Id of the notarization session.
    #[builder(setter(into))]
    id: String,
    /// The server DNS name.
    #[builder(setter(into))]
    server_dns: String,
    /// TLS root certificate store.
    #[builder(setter(strip_option), default = "default_root_store()")]
    pub(crate) root_cert_store: RootCertStore,
    /// Maximum transcript size in bytes
    ///
    /// This includes the number of bytes sent and received to the server.
    #[builder(default = "DEFAULT_MAX_TRANSCRIPT_SIZE")]
    max_transcript_size: usize,
    /// Hash algorithm used for the attestation.
    #[builder(default = "HashAlgorithm::Blake3")]
    attestation_hash_alg: HashAlgorithm,
    /// Hash algorithm used for field commitments.
    #[builder(default = "HashAlgorithm::Blake3")]
    field_commitment_alg: HashAlgorithm,
}

impl ProverConfig {
    /// Create a new builder for `ProverConfig`.
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }

    /// Get the maximum transcript size in bytes.
    pub fn max_transcript_size(&self) -> usize {
        self.max_transcript_size
    }

    /// Returns the server DNS name.
    pub fn server_dns(&self) -> &str {
        &self.server_dns
    }

    /// Returns the attestation hash algorithm.
    pub fn attestation_hash_alg(&self) -> HashAlgorithm {
        self.attestation_hash_alg
    }

    /// Returns the field commitment hash algorithm.
    pub fn field_commitment_alg(&self) -> HashAlgorithm {
        self.field_commitment_alg
    }

    pub(crate) fn build_mpc_tls_config(&self) -> MpcTlsLeaderConfig {
        MpcTlsLeaderConfig::builder()
            .common(
                MpcTlsCommonConfig::builder()
                    .id(format!("{}/mpc_tls", &self.id))
                    .max_transcript_size(self.max_transcript_size)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    pub(crate) fn build_base_ot_sender_config(&self) -> chou_orlandi::SenderConfig {
        chou_orlandi::SenderConfig::builder()
            .receiver_commit()
            .build()
            .unwrap()
    }

    pub(crate) fn build_base_ot_receiver_config(&self) -> chou_orlandi::ReceiverConfig {
        chou_orlandi::ReceiverConfig::default()
    }

    pub(crate) fn build_ot_sender_config(&self) -> kos::SenderConfig {
        kos::SenderConfig::default()
    }

    pub(crate) fn build_ot_receiver_config(&self) -> kos::ReceiverConfig {
        kos::ReceiverConfig::builder()
            .sender_commit()
            .build()
            .unwrap()
    }

    pub(crate) fn ot_count(&self) -> usize {
        self.max_transcript_size * 8
    }

    pub(crate) fn build_p256_sender_config(&self) -> SenderConfig {
        SenderConfig::builder().id("p256/0").build().unwrap()
    }

    pub(crate) fn build_p256_receiver_config(&self) -> ReceiverConfig {
        ReceiverConfig::builder().id("p256/1").build().unwrap()
    }

    pub(crate) fn build_gf2_config(&self) -> SenderConfig {
        SenderConfig::builder().id("gf2").record().build().unwrap()
    }
}

/// Default root store using mozilla certs.
fn default_root_store() -> RootCertStore {
    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));

    root_store
}
