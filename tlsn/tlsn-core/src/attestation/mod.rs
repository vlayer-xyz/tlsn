mod builder;
mod proof;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    conn::{CertificateData, ConnectionInfo, HandshakeData, ServerIdentity, ServerIdentityProof},
    encoding::{EncodingCommitment, EncodingTree},
    hash::{Hash, HashAlgorithm, PlaintextHash},
    merkle::MerkleTree,
    serialize::CanonicalSerialize,
    transcript::SubsequenceIdx,
    Signature, Transcript,
};

pub use builder::{AttestationBodyBuilder, AttestationBodyBuilderError};
pub use proof::BodyProof;

/// The current version of attestations.
pub static ATTESTATION_VERSION: AttestationVersion = AttestationVersion(0);

pub(crate) const ATTESTATION_VERSION_LEN: usize = 4;
pub(crate) const ATTESTATION_ID_LEN: usize = 16;

#[derive(Debug)]
pub struct AttestationError;

/// An identifier for an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationId(pub [u8; ATTESTATION_ID_LEN]);

impl From<[u8; ATTESTATION_ID_LEN]> for AttestationId {
    fn from(id: [u8; ATTESTATION_ID_LEN]) -> Self {
        Self(id)
    }
}

/// The version of an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationVersion(u32);

impl AttestationVersion {
    pub(crate) fn to_le_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// A secret hidden from the Notary.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Secret {
    /// The certificate chain and signature.
    #[serde(rename = "cert")]
    Certificate(CertificateData),
    /// The server's identity.
    #[serde(rename = "server_identity")]
    ServerIdentity(ServerIdentity),
    /// A merkle tree of transcript encodings.
    #[serde(rename = "encoding")]
    EncodingTree(EncodingTree),
    /// A hash of a range of plaintext in the transcript.
    #[serde(rename = "hash")]
    PlaintextHash {
        /// The subsequence of the transcript.
        seq: SubsequenceIdx,
        /// The nonce which was hashed with the plaintext.
        nonce: [u8; 16],
        /// The id of the plaintext hash public field.
        commitment: FieldId,
    },
}

opaque_debug::implement!(Secret);

/// A public attestation field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Field {
    /// TLS connection information.
    #[serde(rename = "info")]
    ConnectionInfo(ConnectionInfo),
    /// TLS handshake data.
    #[serde(rename = "handshake")]
    HandshakeData(HandshakeData),
    /// Commitment to the server's certificate and signature.
    #[serde(rename = "cert")]
    CertificateCommitment(Hash),
    /// Commitment to the certificate chain.
    #[serde(rename = "cert_chain")]
    CertificateChainCommitment(Hash),
    /// Commitment to the encodings of the transcript plaintext.
    #[serde(rename = "encoding")]
    EncodingCommitment(EncodingCommitment),
    /// A hash of a range of plaintext in the transcript.
    #[serde(rename = "hash")]
    PlaintextHash(PlaintextHash),
    /// Arbitrary extra data bound to the attestation.
    #[serde(rename = "extra")]
    ExtraData(Vec<u8>),
}

impl Field {
    /// Returns the kind of the field.
    pub fn kind(&self) -> FieldKind {
        match self {
            Field::ConnectionInfo(_) => FieldKind::ConnectionInfo,
            Field::HandshakeData(_) => FieldKind::HandshakeData,
            Field::CertificateCommitment(_) => FieldKind::CertificateCommitment,
            Field::CertificateChainCommitment(_) => FieldKind::CertificateChainCommitment,
            Field::EncodingCommitment(_) => FieldKind::EncodingCommitment,
            Field::PlaintextHash(_) => FieldKind::PlaintextHash,
            Field::ExtraData(_) => FieldKind::ExtraData,
        }
    }
}

/// The kind of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FieldKind {
    /// TLS connection information.
    ConnectionInfo = 0x00,
    /// TLS handshake data.
    HandshakeData = 0x01,
    /// Commitment to the server's certificate and signature.
    CertificateCommitment = 0x02,
    /// Commitment to the certificate chain.
    CertificateChainCommitment = 0x03,
    /// Commitment to the encodings of the transcript plaintext.
    EncodingCommitment = 0x04,
    /// A hash of a range of plaintext in the transcript.
    PlaintextHash = 0x05,
    /// Arbitrary extra data bound to the attestation.
    ExtraData = 0xff,
}

/// An identifier for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FieldId(pub u32);

/// An attestation header.
///
/// A header is the data structure which is signed by the Notary. It contains
/// a unique idenitifer, the protocol version, and a Merkle root of the
/// attestation fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationHeader {
    /// An identifier for the attestation.
    pub id: AttestationId,
    /// Version of the attestation.
    pub version: AttestationVersion,
    /// Merkle root of the attestation fields.
    pub root: Hash,
}

impl AttestationHeader {
    /// Serializes the header to its canonical form.
    pub fn serialize(&self) -> Vec<u8> {
        CanonicalSerialize::serialize(self)
    }
}

/// The body of an attestation.
///
/// An attestation contains a set of fields which are cryptographically signed by
/// the Notary via an [`AttestationHeader`]. These fields include data which can be
/// used to verify aspects of a TLS connection, such as the server's identity, and facts
/// about the transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBody {
    /// The fields of the attestation.
    pub(crate) fields: HashMap<FieldId, Field>,
}

impl AttestationBody {
    /// Computes the Merkle root of the attestation fields.
    pub fn root(&self, alg: HashAlgorithm) -> Hash {
        let mut tree = MerkleTree::new(alg);
        let mut fields = self.fields.iter().collect::<Vec<_>>();
        fields.sort_by_key(|(id, _)| *id);

        for (_, field) in fields {
            tree.insert(field)
        }

        tree.root()
    }

    /// Returns the field with the given id.
    pub fn get(&self, id: &FieldId) -> Option<&Field> {
        self.fields.get(id)
    }

    /// Returns an iterator over the fields.
    pub fn iter(&self) -> impl Iterator<Item = (&FieldId, &Field)> {
        self.fields.iter()
    }

    pub(crate) fn get_info(&self) -> Option<&ConnectionInfo> {
        self.fields.iter().find_map(|(_, field)| match field {
            Field::ConnectionInfo(info) => Some(info),
            _ => None,
        })
    }

    pub(crate) fn get_encoding_commitment(&self) -> Option<&EncodingCommitment> {
        self.fields.iter().find_map(|(_, field)| match field {
            Field::EncodingCommitment(commitment) => Some(commitment),
            _ => None,
        })
    }
}

/// An attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// The signature of the attestation.
    pub sig: Signature,
    /// The attestation header.
    pub header: AttestationHeader,
    /// The attestation body.
    pub body: AttestationBody,
}

impl Attestation {
    /// Creates a new attestation builder.
    pub fn builder() -> AttestationBodyBuilder {
        AttestationBodyBuilder::default()
    }
}

/// The full data of an attestation, including private fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationFull {
    /// The signature of the attestation.
    pub sig: Signature,
    /// The attestation header.
    pub header: AttestationHeader,
    /// The attestation body.
    pub body: AttestationBody,
    /// Transcript of data communicated between the Prover and the Server.
    pub transcript: Transcript,
    /// Secret data of the attestation.
    pub secrets: Vec<Secret>,
}

impl AttestationFull {
    /// Returns a server identity proof.
    pub fn identity_proof(&self) -> Result<ServerIdentityProof, AttestationError> {
        let cert_data = self
            .secrets
            .iter()
            .find_map(|secret| match secret {
                Secret::Certificate(cert_data) => Some(cert_data),
                _ => None,
            })
            .unwrap();

        let identity = self
            .secrets
            .iter()
            .find_map(|secret| match secret {
                Secret::ServerIdentity(identity) => Some(identity.clone()),
                _ => None,
            })
            .unwrap();

        Ok(ServerIdentityProof {
            cert_data: cert_data.clone(),
            identity,
        })
    }
}
