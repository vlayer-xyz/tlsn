use tlsn_core::session::NotarizedSession;

use p256::ecdsa::SigningKey;

static NOTARIZED_SESSION_BYTES: &[u8] = include_bytes!("notarized_session.bin");

pub fn notarized_session() -> NotarizedSession {
    bincode::deserialize(NOTARIZED_SESSION_BYTES).expect("notarized session data is valid")
}

pub fn notary_signing_key() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}
