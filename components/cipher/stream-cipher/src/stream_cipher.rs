use async_trait::async_trait;
use mpz_circuits::types::Value;
use std::collections::HashMap;
use tracing::instrument;

use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Execute, Load, Prove, Thread, Verify};
use utils::id::NestedId;

use crate::{
    cipher::CtrCircuit,
    circuit::build_array_xor,
    config::{is_valid_mode, ExecutionMode, InputText, StreamCipherConfig},
    keystream::CipherRefs,
    StreamCipher, StreamCipherError, ZkProve,
};

/// An MPC stream cipher.
#[derive(Debug)]
pub struct MpcStreamCipher<E>
where
    E: Thread + Execute + Decode + DecodePrivate + Send + Sync,
{
    config: StreamCipherConfig,
    counter: usize,
    thread: E,
}

/// A subset of plaintext bytes processed by the stream cipher.
///
/// Note that `Transcript` does not store the actual bytes. Instead, it provides IDs which are
/// assigned to plaintext bytes of the stream cipher.
struct Transcript {
    /// The ID of this transcript.
    id: String,
    /// The ID for the next plaintext byte.
    plaintext: NestedId,
}

impl Transcript {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            plaintext: NestedId::new(id).append_counter(),
        }
    }

    /// Returns unique identifiers for the next plaintext bytes in the transcript.
    fn extend_plaintext(&mut self, len: usize) -> Vec<String> {
        (0..len)
            .map(|_| self.plaintext.increment_in_place().to_string())
            .collect()
    }
}

impl<E> MpcStreamCipher<E>
where
    E: Thread + Execute + Load + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    /// Creates a new counter-mode cipher.
    pub fn new(config: StreamCipherConfig, thread: E) -> Self {
        Self {
            config,
            counter: 0,
            thread,
        }
    }

    async fn decode_public(&mut self, value: ValueRef) -> Result<Value, StreamCipherError> {
        self.thread
            .decode(&[value])
            .await
            .map_err(StreamCipherError::from)
            .map(|mut output| output.pop().unwrap())
    }

    async fn decode_shared(&mut self, value: ValueRef) -> Result<Value, StreamCipherError> {
        self.thread
            .decode_shared(&[value])
            .await
            .map_err(StreamCipherError::from)
            .map(|mut output| output.pop().unwrap())
    }

    async fn decode_private(&mut self, value: ValueRef) -> Result<Value, StreamCipherError> {
        self.thread
            .decode_private(&[value])
            .await
            .map_err(StreamCipherError::from)
            .map(|mut output| output.pop().unwrap())
    }

    async fn decode_blind(&mut self, value: ValueRef) -> Result<(), StreamCipherError> {
        self.thread.decode_blind(&[value]).await?;
        Ok(())
    }

    async fn prove(&mut self, value: ValueRef) -> Result<(), StreamCipherError> {
        self.thread.prove(&[value]).await?;
        Ok(())
    }

    async fn verify(&mut self, value: ValueRef, expected: Value) -> Result<(), StreamCipherError> {
        self.thread.verify(&[value], &[expected]).await?;
        Ok(())
    }
}

#[async_trait]
impl<C, E> StreamCipher<C> for MpcStreamCipher<E>
where
    C: CtrCircuit,
    E: Thread + Execute + Load + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        cipher_refs: CipherRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        cipher_refs: CipherRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        len: usize,
        cipher_refs: CipherRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        cipher_refs: CipherRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        cipher_refs: CipherRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        cipher_refs: CipherRefs<C>,
    ) -> Result<(), StreamCipherError> {
        todo!()
    }
}

#[async_trait]
impl<C, E> ZkProve<C> for MpcStreamCipher<E>
where
    C: CtrCircuit,
    E: Thread + Execute + Load + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    #[instrument(level = "debug", skip_all, err)]
    async fn prove_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        cipher_refs: CipherRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn verify_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        cipher_refs: CipherRefs<C>,
    ) -> Result<(), StreamCipherError> {
        todo!()
    }
}
