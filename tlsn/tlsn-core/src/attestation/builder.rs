use crate::{
    attestation::{
        AttestationBody, CertChainCommitment, CertCommitment, EncodingCommitment, ExtraData, Field,
        FieldId,
    },
    conn::{ConnectionInfo, HandshakeData},
    hash::PlaintextHash,
};

#[derive(Debug, thiserror::Error)]
#[error("attestation body builder error: {0}")]
pub struct AttestationBodyBuilderError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl AttestationBodyBuilderError {
    fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(error.into())
    }
}

/// A builder for constructing an attestation body.
#[derive(Debug, Default)]
pub struct AttestationBodyBuilder {
    conn_info: Option<ConnectionInfo>,
    handshake_data: Option<HandshakeData>,
    cert_commitment: Option<CertCommitment>,
    cert_chain_commitment: Option<CertChainCommitment>,
    encoding_commitment: Option<EncodingCommitment>,
    plaintext_hashes: Vec<PlaintextHash>,
    extra_data: Vec<ExtraData>,
}

impl AttestationBodyBuilder {
    /// Builds the attestation.
    pub fn build(self) -> Result<AttestationBody, AttestationBodyBuilderError> {
        let mut field_id = FieldId(0);

        let conn_info = Field::new(
            field_id.next(),
            self.conn_info
                .ok_or_else(|| AttestationBodyBuilderError::new("missing connection info"))?,
        );

        let handshake_data = Field::new(
            field_id.next(),
            self.handshake_data
                .ok_or_else(|| AttestationBodyBuilderError::new("missing handshake data"))?,
        );

        let cert_commitment = Field::new(
            field_id.next(),
            self.cert_commitment.ok_or_else(|| {
                AttestationBodyBuilderError::new("missing certificate commitment")
            })?,
        );

        let cert_chain_commitment = Field::new(
            field_id.next(),
            self.cert_chain_commitment.ok_or_else(|| {
                AttestationBodyBuilderError::new("missing certificate chain commitment")
            })?,
        );

        let encoding_commitment = if let Some(commitment) = self.encoding_commitment {
            Some(Field::new(field_id.next(), commitment))
        } else {
            None
        };

        let plaintext_hashes = self
            .plaintext_hashes
            .into_iter()
            .map(|hash| Field::new(field_id.next(), hash))
            .collect();

        let extra_data = self
            .extra_data
            .into_iter()
            .map(|data| Field::new(field_id.next(), data))
            .collect();

        Ok(AttestationBody {
            conn_info,
            handshake_data,
            cert_commitment,
            cert_chain_commitment,
            encoding_commitment,
            plaintext_hashes,
            extra_data,
        })
    }
}
