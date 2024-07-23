pub mod cipher;
pub mod circuit;
pub mod config;

use crate::error::AesGcmError;
use cipher::CtrCircuit;
use mpz_garble::{value::ValueRef, Load, Thread};
use tracing::instrument;
use utils::id::NestedId;

#[derive(Debug)]
pub struct KeystreamCreator {
    key: Option<ValueRef>,
    iv: Option<ValueRef>,
    block_counter: NestedId,
    preprocessed: Option<KeyStreamRefs>,
}

impl KeystreamCreator {
    pub fn new(id: &str) -> Self {
        let block_counter = NestedId::new(id).append_counter();
        Self {
            key: None,
            iv: None,
            block_counter,
            preprocessed: None,
        }
    }

    pub fn set_key(&mut self, key: ValueRef) {
        self.key = Some(key);
    }

    pub fn set_iv(&mut self, iv: ValueRef) {
        self.iv = Some(iv);
    }

    #[instrument(level = "debug", skip_all, err)]
    pub async fn preprocess<C, T>(&mut self, thread: &mut T, len: usize) -> Result<(), AesGcmError>
    where
        C: CtrCircuit,
        T: Thread + Load,
    {
        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;
        let calls = self.define_cipher_refs::<C, T>(block_count)?;

        let inputs = calls.iter_inputs();
        let outputs = calls.iter_outputs();
        for (input, output) in inputs.zip(outputs) {
            thread.load(C::circuit(), input.as_ref(), &[output]).await?;
        }

        if let Some(preprocessed) = self.preprocessed.as_mut() {
            preprocessed.extend(calls);
        } else {
            self.preprocessed = Some(calls);
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub async fn compute_keystream<C, T>(
        &mut self,
        thread: &mut T,
        explicit_nonce: Vec<u8>,
        start_ctr: usize,
        len: usize,
    ) -> Result<KeyStreamRefs, AesGcmError>
    where
        C: CtrCircuit,
        T: Thread + Load,
    {
        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;

        // Take any preprocessed blocks if available, and define new ones if needed.
        let cipher_refs = if let Some(preprocessed) = self.preprocessed.as_mut() {
            let mut calls = preprocessed.drain(block_count);
            calls.extend(self.define_cipher_refs::<C, T>(block_count - calls.len())?);
            calls
        } else {
            self.define_cipher_refs::<C, T>(block_count)?
        };

        cipher_refs.assign::<C, T>(thread, explicit_nonce, start_ctr)?;
        Ok(cipher_refs)
    }

    fn key(&self) -> Result<ValueRef, AesGcmError> {
        self.key.clone().ok_or_else(AesGcmError::key_not_set)
    }

    fn iv(&self) -> Result<ValueRef, AesGcmError> {
        self.iv.clone().ok_or_else(AesGcmError::iv_not_set)
    }

    fn define_cipher_refs<C, T>(&mut self, count: usize) -> Result<KeyStreamRefs, AesGcmError>
    where
        C: CtrCircuit,
        T: Load + Thread,
    {
        let mut calls = KeyStreamRefs::new(self.key()?, self.iv()?);
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

#[derive(Debug)]
pub struct KeyStreamRefs {
    key: ValueRef,
    iv: ValueRef,
    nonces: Vec<ValueRef>,
    ctrs: Vec<ValueRef>,
    blocks: Vec<ValueRef>,
}

impl KeyStreamRefs {
    fn new(key: ValueRef, iv: ValueRef) -> Self {
        KeyStreamRefs {
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

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    fn drain(&mut self, mut count: usize) -> KeyStreamRefs {
        if count > self.len() {
            count = self.len();
        }

        let nonces = self.nonces.drain(0..count).collect();
        let ctrs = self.ctrs.drain(0..count).collect();
        let blocks = self.blocks.drain(0..count).collect();

        KeyStreamRefs {
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

    fn extend(&mut self, vars: KeyStreamRefs) {
        self.nonces.extend(vars.nonces);
        self.ctrs.extend(vars.ctrs);
        self.blocks.extend(vars.blocks);
    }

    pub fn iter_inputs<'a>(&'a self) -> impl Iterator<Item = [ValueRef; 4]> + 'a {
        self.nonces
            .iter()
            .cloned()
            .zip(self.ctrs.iter().cloned())
            .map(|(nonce, ctr)| [self.key.clone(), self.iv.clone(), nonce, ctr])
    }

    pub fn iter_outputs(&self) -> impl Iterator<Item = ValueRef> + '_ {
        self.blocks.iter().cloned()
    }

    pub fn assign<C, T>(
        &self,
        thread: &mut T,
        explicit_nonce: Vec<u8>,
        start_ctr: usize,
    ) -> Result<(), AesGcmError>
    where
        C: CtrCircuit,
        T: Load + Thread,
    {
        let explicit_nonce_len = explicit_nonce.len();
        let explicit_nonce: C::NONCE = explicit_nonce
            .try_into()
            .map_err(|_| AesGcmError::explicit_nonce_len::<C>(explicit_nonce_len))?;

        for (k, [_, _, nonce, ctr]) in self.iter_inputs().enumerate() {
            thread.assign(&nonce, explicit_nonce)?;
            thread.assign(&ctr, ((start_ctr + k) as u32).to_be_bytes())?;
        }
        Ok(())
    }

    pub fn take_blocks(&self, len: usize) -> Vec<ValueRef> {
        self.blocks
            .iter()
            .flat_map(|block| block.iter())
            .cloned()
            .take(len)
            .map(|byte| ValueRef::Value { id: byte })
            .collect()
    }

    pub async fn compute<C, T>(self) -> Result<ValueRef, AesGcmError>
    where
        C: CtrCircuit,
        T: Load + Thread,
    {
        todo!()
    }
}
