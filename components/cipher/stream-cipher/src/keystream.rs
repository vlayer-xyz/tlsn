use crate::{CtrCircuit, KeyStream, StreamCipherError};
use async_trait::async_trait;
use mpz_circuits::Circuit;
use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Execute, Load, Thread};
use std::{collections::VecDeque, marker::PhantomData, sync::Arc};
use tracing::instrument;
use utils::id::NestedId;

pub(crate) struct MpcKeyStream<C, E> {
    thread: E,
    key: Option<ValueRef>,
    iv: Option<ValueRef>,
    block_counter: NestedId,
    preprocessed: Option<Calls>,
    _pd: PhantomData<C>,
}

impl<C, E> MpcKeyStream<C, E>
where
    C: CtrCircuit,
    E: Thread + Load + Execute + Decode + DecodePrivate + Send + Sync,
{
    pub(crate) fn new(id: &str, thread: E) -> Self {
        let block_counter = NestedId::new(id).append_counter();
        Self {
            key: None,
            iv: None,
            thread,
            block_counter,
            preprocessed: None,
            _pd: PhantomData,
        }
    }

    fn key(&self) -> Result<ValueRef, StreamCipherError> {
        self.key
            .clone()
            .ok_or_else(|| StreamCipherError::key_not_set())
    }

    fn iv(&self) -> Result<ValueRef, StreamCipherError> {
        self.iv
            .clone()
            .ok_or_else(|| StreamCipherError::iv_not_set())
    }

    fn define_calls(&mut self, count: usize) -> Result<Calls, StreamCipherError> {
        let mut calls = Calls::new(self.key()?, self.iv()?);
        for _ in 0..count {
            let block_id = self.block_counter.increment_in_place();
            let nonce = self
                .thread
                .new_public_input::<C::NONCE>(&block_id.append_string("nonce").to_string())?;
            let ctr = self
                .thread
                .new_public_input::<[u8; 4]>(&block_id.append_string("ctr").to_string())?;
            let block = self.thread.new_output::<C::BLOCK>(&block_id.to_string())?;

            calls.push(nonce, ctr, block);
        }

        Ok(calls)
    }
}

#[async_trait]
impl<C, E> KeyStream for MpcKeyStream<C, E>
where
    C: CtrCircuit,
    E: Thread + Load + Execute + Decode + DecodePrivate + Send + Sync,
{
    fn set_key_and_iv(&mut self, key: ValueRef, iv: ValueRef) {
        self.key = Some(key);
        self.iv = Some(iv);
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess(&mut self, len: usize) -> Result<(), StreamCipherError> {
        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;
        let calls = self.define_calls(block_count)?;

        let inputs = calls.iter_inputs();
        let outputs = calls.iter_outputs();
        for (input, output) in inputs.zip(outputs) {
            self.thread
                .load(C::circuit(), input.as_ref(), &[output])
                .await?;
        }

        if let Some(preprocessed) = self.preprocessed.as_mut() {
            preprocessed.extend(calls);
        } else {
            self.preprocessed = Some(calls);
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn setup_keystream(
        &mut self,
        explicit_nonce: Vec<u8>,
        start_ctr: usize,
        len: usize,
    ) -> Result<Calls, StreamCipherError> {
        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;

        // Take any preprocessed blocks if available, and define new ones if needed.
        let calls = if let Some(preprocessed) = self.preprocessed.as_mut() {
            let mut calls = preprocessed.drain(block_count);
            calls.extend(self.define_calls(block_count - calls.len())?);
            calls
        } else {
            self.define_calls(block_count)?
        };

        calls.assign::<C, E>(&mut self.thread, explicit_nonce, start_ctr)?;
        Ok(calls)
    }

    async fn share_zero_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: usize,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let keystream = self.setup_keystream(explicit_nonce, 1, 1).await?;
        todo!()
    }
}

#[derive(Debug)]
struct Calls {
    key: ValueRef,
    iv: ValueRef,
    nonces: Vec<ValueRef>,
    ctrs: Vec<ValueRef>,
    blocks: Vec<ValueRef>,
}

impl Calls {
    fn new(key: ValueRef, iv: ValueRef) -> Self {
        Calls {
            key,
            iv,
            nonces: Vec::default(),
            ctrs: Vec::default(),
            blocks: Vec::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }

    fn drain(&mut self, count: usize) -> Calls {
        let nonces = self.nonces.drain(0..count).collect();
        let ctrs = self.ctrs.drain(0..count).collect();
        let blocks = self.blocks.drain(0..count).collect();

        Calls {
            key: self.key.clone(),
            iv: self.iv.clone(),
            nonces,
            ctrs,
            blocks,
        }
    }

    fn push(&mut self, nonce: ValueRef, ctr: ValueRef, block: ValueRef) {
        self.nonces.push(nonce);
        self.ctrs.push(ctr);
        self.blocks.push(block);
    }

    fn extend(&mut self, vars: Calls) {
        self.nonces.extend(vars.nonces);
        self.ctrs.extend(vars.ctrs);
        self.blocks.extend(vars.blocks);
    }

    fn iter_inputs<'a>(&'a self) -> impl Iterator<Item = [ValueRef; 4]> + 'a {
        self.nonces
            .iter()
            .cloned()
            .zip(self.ctrs.iter().cloned())
            .map(|(nonce, ctr)| [self.key.clone(), self.iv.clone(), nonce, ctr])
    }

    fn iter_outputs(&self) -> impl Iterator<Item = ValueRef> + '_ {
        self.blocks.iter().cloned()
    }

    fn assign<C: CtrCircuit, E: Thread>(
        &self,
        thread: &mut E,
        explicit_nonce: Vec<u8>,
        start_ctr: usize,
    ) -> Result<(), StreamCipherError> {
        let explicit_nonce_len = explicit_nonce.len();
        let explicit_nonce: C::NONCE = explicit_nonce
            .try_into()
            .map_err(|_| StreamCipherError::explicit_nonce_len::<C>(explicit_nonce_len))?;

        for (k, [_, _, nonce, ctr]) in self.iter_inputs().enumerate() {
            thread.assign(&nonce, explicit_nonce)?;
            thread.assign(&ctr, ((start_ctr + k) as u32).to_be_bytes())?;
        }
        Ok(())
    }

    fn take_blocks(&self, len: usize) -> Vec<ValueRef> {
        self.blocks
            .iter()
            .flat_map(|block| block.iter())
            .cloned()
            .take(len)
            .map(|byte| ValueRef::Value { id: byte })
            .collect()
    }
}
