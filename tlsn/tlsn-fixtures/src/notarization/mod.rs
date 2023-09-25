use std::collections::HashMap;

use mpz_circuits::types::ValueType;
use mpz_core::{hash::Hash, value::ValueId};
use mpz_garble_core::{encoding_state, ChaChaEncoder, EncodedValue, Encoder};
use tls_core::{key::PublicKey, msgs::enums::NamedGroup};
use tlsn_core::{
    merkle::MerkleRoot,
    session::{HandshakeSummary, NotarizedSession, SessionHeader},
    transcript::Transcript,
};

use p256::ecdsa::SigningKey;

static NOTARIZED_SESSION_BYTES: &[u8] = include_bytes!("notarized_session.bin");

type EncodingProvider =
    Box<dyn Fn(&[&str]) -> Option<Vec<EncodedValue<encoding_state::Active>>> + Send>;

pub fn notarized_session() -> NotarizedSession {
    bincode::deserialize(NOTARIZED_SESSION_BYTES).expect("notarized session data is valid")
}

pub fn handshake_summary() -> HandshakeSummary {
    HandshakeSummary::new(
        0,
        PublicKey::new(NamedGroup::secp256r1, &[1u8; 32]),
        Hash::from([0u8; 32]),
    )
}

pub fn session_header_with_data(
    root: MerkleRoot,
    sent_len: usize,
    recv_len: usize,
) -> SessionHeader {
    SessionHeader::new(
        encoder_seed(),
        root,
        sent_len,
        recv_len,
        handshake_summary(),
    )
}

pub fn notary_signing_key() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}

pub fn encoding_provider_with_data(transcript_tx: &[u8], transcript_rx: &[u8]) -> EncodingProvider {
    let encoder = encoder();
    let mut active_encodings = HashMap::new();
    for (idx, byte) in transcript_tx.iter().enumerate() {
        let id = format!("tx/{idx}");
        let enc = encoder.encode_by_type(ValueId::new(&id).to_u64(), &ValueType::U8);
        active_encodings.insert(id, enc.select(*byte).unwrap());
    }
    for (idx, byte) in transcript_rx.iter().enumerate() {
        let id = format!("rx/{idx}");
        let enc = encoder.encode_by_type(ValueId::new(&id).to_u64(), &ValueType::U8);
        active_encodings.insert(id, enc.select(*byte).unwrap());
    }

    Box::new(move |ids: &[&str]| {
        ids.iter()
            .map(|id| active_encodings.get(*id).cloned())
            .collect()
    })
}

pub fn encoder() -> ChaChaEncoder {
    ChaChaEncoder::new(encoder_seed())
}

pub fn encoder_seed() -> [u8; 32] {
    [0u8; 32]
}
