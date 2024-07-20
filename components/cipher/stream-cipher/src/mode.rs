use async_trait::async_trait;
use mpz_circuits::types::Value;
use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Thread};

use crate::StreamCipherError;

pub struct TextRefs<M: Mode> {
    input: Vec<ValueRef>,
    output: Vec<ValueRef>,
    phantom: M,
}

impl<M: Mode> TextRefs<M> {
    pub fn len(&self) -> usize {
        self.input.len()
    }

    pub fn input(&self) -> &[ValueRef] {
        &self.input
    }

    pub fn output(&self) -> &[ValueRef] {
        &self.output
    }
}

pub struct Public;
pub struct Private;
pub struct Blind;
pub struct Shared;

#[async_trait]
pub trait Mode: sealed::Sealed + Send + Sync + 'static {
    type Output;

    async fn decode<E>(
        thread: &mut E,
        output_text: &[ValueRef],
    ) -> Result<Self::Output, StreamCipherError>
    where
        E: Thread + Decode + DecodePrivate + Send;
}

#[async_trait]
impl Mode for Public {
    type Output = Vec<Value>;

    async fn decode<E>(
        thread: &mut E,
        output_text: &[ValueRef],
    ) -> Result<Self::Output, StreamCipherError>
    where
        E: Thread + Decode + DecodePrivate + Send,
    {
        thread
            .decode(output_text)
            .await
            .map_err(StreamCipherError::from)
    }
}

#[async_trait]
impl Mode for Private {
    type Output = Vec<Value>;

    async fn decode<E>(
        thread: &mut E,
        output_text: &[ValueRef],
    ) -> Result<Self::Output, StreamCipherError>
    where
        E: Thread + Decode + DecodePrivate + Send,
    {
        thread
            .decode_private(output_text)
            .await
            .map_err(StreamCipherError::from)
    }
}

#[async_trait]
impl Mode for Blind {
    type Output = ();

    async fn decode<E>(
        thread: &mut E,
        output_text: &[ValueRef],
    ) -> Result<Self::Output, StreamCipherError>
    where
        E: Thread + Decode + DecodePrivate + Send,
    {
        thread
            .decode_blind(output_text)
            .await
            .map_err(StreamCipherError::from)
    }
}

#[async_trait]
impl Mode for Shared {
    type Output = Vec<Value>;

    async fn decode<E>(
        thread: &mut E,
        output_text: &[ValueRef],
    ) -> Result<Self::Output, StreamCipherError>
    where
        E: Thread + Decode + DecodePrivate + Send,
    {
        thread
            .decode_shared(output_text)
            .await
            .map_err(StreamCipherError::from)
    }
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Public {}
    impl Sealed for super::Private {}
    impl Sealed for super::Blind {}
    impl Sealed for super::Shared {}
}
