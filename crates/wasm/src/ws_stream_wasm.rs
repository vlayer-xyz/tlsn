use std::{
    fmt::Display,
    pin::Pin,
    task::{Context, Poll},
};

use async_io_stream::IoStream;
use futures::{io, Sink, Stream};
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

impl Stream for WsStreamIo {
    type Item = Result<Vec<u8>, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        todo!()
        // Pin::new(&mut self.inner)
        //     .poll_next(cx)
        //     .map(|opt| opt.map(|msg| Ok(msg.into())))
    }
}

impl Sink<Vec<u8>> for WsStreamIo {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
        // Pin::new(&mut self.inner)
        //     .poll_ready(cx)
        //     .map(convert_res_tuple)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        todo!()
        // Pin::new(&mut self.inner)
        //     .start_send(item.into())
        //     .map_err(convert_err)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
        // Pin::new(&mut self.inner)
        //     .poll_flush(cx)
        //     .map(convert_res_tuple)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
        // Pin::new(&mut self.inner)
        //     .poll_close(cx)
        //     .map(convert_res_tuple)
    }
}

fn convert_res_tuple(res: Result<(), WsErr>) -> Result<(), io::Error> {
    res.map_err(convert_err)
}

fn convert_err(err: WsErr) -> io::Error {
    match err {
        WsErr::ConnectionNotOpen => return io::Error::from(io::ErrorKind::NotConnected),

        // This shouldn't happen, so panic for early detection.
        _ => unreachable!(),
    }
}
