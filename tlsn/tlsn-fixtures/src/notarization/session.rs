use tlsn_core::session::NotarizedSession;

static NOTARIZED_SESSION_BYTES: &[u8] = include_bytes!("notarized_session");

pub fn notarized_session() -> NotarizedSession {
    bincode::deserialize(NOTARIZED_SESSION_BYTES).expect("notarized session data is valid")
}
