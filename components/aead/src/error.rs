use crate::keystream::cipher::CtrCircuit;
use std::fmt::Display;

/// AES-GCM error.
#[derive(Debug, thiserror::Error)]
pub struct AesGcmError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl AesGcmError {
    pub(crate) fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub(crate) fn invalid_tag() -> Self {
        Self {
            kind: ErrorKind::Tag,
            source: None,
        }
    }

    pub(crate) fn peer(reason: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::PeerMisbehaved,
            source: Some(reason.into().into()),
        }
    }

    pub(crate) fn payload(reason: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Payload,
            source: Some(reason.into().into()),
        }
    }

    pub(crate) fn key_len<C: CtrCircuit>(len: usize) -> Self {
        Self {
            kind: ErrorKind::Key,
            source: Some(
                format!("invalid key length: expected {}, got {}", C::KEY_LEN, len).into(),
            ),
        }
    }

    pub(crate) fn iv_len<C: CtrCircuit>(len: usize) -> Self {
        Self {
            kind: ErrorKind::Iv,
            source: Some(format!("invalid iv length: expected {}, got {}", C::IV_LEN, len).into()),
        }
    }

    pub(crate) fn explicit_nonce_len<C: CtrCircuit>(len: usize) -> Self {
        Self {
            kind: ErrorKind::ExplicitNonce,
            source: Some(
                format!(
                    "invalid explicit nonce length: expected {}, got {}",
                    C::NONCE_LEN,
                    len
                )
                .into(),
            ),
        }
    }

    pub(crate) fn key_not_set() -> Self {
        Self {
            kind: ErrorKind::Key,
            source: Some("key not set".into()),
        }
    }

    pub(crate) fn iv_not_set() -> Self {
        Self {
            kind: ErrorKind::Iv,
            source: Some(format!("iv not set").into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ErrorKind {
    Io,
    BlockCipher,
    Ghash,
    Tag,
    PeerMisbehaved,
    Payload,
    Key,
    Iv,
    ExplicitNonce,
    Vm,
}

impl Display for AesGcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Io => write!(f, "io error")?,
            ErrorKind::BlockCipher => write!(f, "block cipher error")?,
            ErrorKind::Ghash => write!(f, "ghash error")?,
            ErrorKind::Tag => write!(f, "payload has corrupted tag")?,
            ErrorKind::PeerMisbehaved => write!(f, "peer misbehaved")?,
            ErrorKind::Payload => write!(f, "payload error")?,
            ErrorKind::Key => write!(f, "key error")?,
            ErrorKind::Iv => write!(f, "iv errror")?,
            ErrorKind::ExplicitNonce => write!(f, "explicit nonce error")?,
            ErrorKind::Vm => write!(f, "vm error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<std::io::Error> for AesGcmError {
    fn from(err: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, err)
    }
}

impl From<block_cipher::BlockCipherError> for AesGcmError {
    fn from(err: block_cipher::BlockCipherError) -> Self {
        Self::new(ErrorKind::BlockCipher, err)
    }
}

impl From<tlsn_universal_hash::UniversalHashError> for AesGcmError {
    fn from(err: tlsn_universal_hash::UniversalHashError) -> Self {
        Self::new(ErrorKind::Ghash, err)
    }
}

impl From<mpz_garble::LoadError> for AesGcmError {
    fn from(err: mpz_garble::LoadError) -> Self {
        Self::new(ErrorKind::Vm, err)
    }
}
