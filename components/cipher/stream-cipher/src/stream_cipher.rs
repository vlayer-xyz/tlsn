use crate::{
    cipher::CtrCircuit, circuit::build_array_xor, config::StreamCipherConfig,
    keystream::KeyStreamRefs, Mode, StreamCipher, StreamCipherError, TextRefs, Transcript, ZkProve,
};
use async_trait::async_trait;
use mpz_circuits::{types::Value, Circuit};
use mpz_garble::{
    value::ValueRef, Decode, DecodePrivate, Execute, ExecutionError, Load, MemoryError, Prove,
    Thread, Verify,
};
use std::{future::Future, sync::Arc};
use tracing::instrument;

/// An MPC stream cipher.
#[derive(Debug)]
pub struct MpcStreamCipher<E> {
    config: StreamCipherConfig,
    counter: usize,
    thread: E,
}

impl<E: Send + Sync + 'static> MpcStreamCipher<E> {
    /// Creates a new counter-mode cipher.
    pub fn new(config: StreamCipherConfig, thread: E) -> Self {
        Self {
            config,
            counter: 0,
            thread,
        }
    }
}

#[async_trait]
impl<C, E> StreamCipher<C> for MpcStreamCipher<E>
where
    C: CtrCircuit,
    E: Thread + Execute + Load + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt<M: Mode>(
        &mut self,
        plaintext: TextRefs<M>,
        keystream: KeyStreamRefs<C>,
    ) -> Result<M::Output, StreamCipherError> {
        if plaintext.len() != keystream.len() {
            return Err(StreamCipherError::unequal_block_len(
                plaintext.len(),
                keystream.len(),
            ));
        }

        let inputs = keystream.iter_inputs();
        let outputs = keystream.iter_outputs();

        for (input, output) in inputs.zip(outputs) {
            self.thread.commit(&input).await?;
            self.thread.execute(C::circuit(), &input, &[output]).await?;
        }

        // Execute XOR circuit.
        let xor_circ = build_array_xor(plaintext.len());

            self.thread
                .execute(xor_circ, &[input, keystream], &[output])
                .await?;
        }

        // Decode
        // 1. Shift encrypt and decrypt to aead crate
        // 2. No decoding at this level, return valueref
        M::decode(&mut self.thread, plaintext.output()).await
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt<M: Mode>(
        &mut self,
        ciphertext: TextRefs<M>,
        keystream_refs: KeyStreamRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError> {
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
        ciphertext: Vec<u8>,
        keystream: KeyStreamRefs<C>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn verify_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        keystream: KeyStreamRefs<C>,
    ) -> Result<(), StreamCipherError> {
        todo!()
    }
}
