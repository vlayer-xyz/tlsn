use std::fmt::Display;

use async_io_stream::IoStream;
use thiserror::Error;

pub struct WsMeta {}

impl WsMeta {
    pub async fn connect(
        url: impl AsRef<str>,
        protocols: impl Into<Option<Vec<&str>>>,
    ) -> Result<(Self, WsStream), WsErr> {
        todo!()
    }
}

pub struct WsStream {}

impl WsStream {
    pub fn into_io(self) -> IoStream<WsStreamIo, Vec<u8>> {
        IoStream::new(WsStreamIo::new(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseEvent {
    pub code: u16,
    pub reason: String,
    pub was_clean: bool,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WsErr {
    InvalidWsState { supplied: u16 },
    ConnectionNotOpen,
    InvalidUrl { supplied: String },
    InvalidCloseCode { supplied: u16 },
    ReasonStringToLong,
    ConnectionFailed { event: CloseEvent },
    InvalidEncoding,
    CantDecodeBlob,
    UnknownDataType,
}

impl Display for WsErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

pub struct WsStreamIo {
    inner: WsStream,
}

impl WsStreamIo {
    /// Create a new WsStreamIo.
    //
    pub fn new(inner: WsStream) -> Self {
        Self { inner }
    }
}
