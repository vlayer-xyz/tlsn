use std::{collections::VecDeque, marker::PhantomData};

use async_trait::async_trait;

use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Execute, Load, Memory};
use tracing::instrument;
use utils::id::NestedId;

use crate::{BlockCipher, BlockCipherCircuit, BlockCipherConfig, BlockCipherError, Visibility};

#[derive(Debug)]
struct State {
    private_execution_id: NestedId,
    public_execution_id: NestedId,
    j0_execution_id: NestedId,
    preprocessed_private: VecDeque<BlockVars>,
    preprocessed_public: VecDeque<BlockVars>,
    preprocessed_j0: VecDeque<CounterVars>,
    key_and_iv: Option<EncodedKeyAndIv>,
}

#[derive(Debug, Clone)]
struct EncodedKeyAndIv {
    key: ValueRef,
    iv: ValueRef,
}

#[derive(Debug)]
struct BlockVars {
    msg: ValueRef,
    ciphertext: ValueRef,
}

#[derive(Debug)]
struct CounterVars {
    nonce: ValueRef,
    ctr: ValueRef,
    ciphertext: ValueRef,
}

/// An MPC block cipher.
#[derive(Debug)]
pub struct MpcBlockCipher<C, E>
where
    C: BlockCipherCircuit,
    E: Memory + Execute + Decode + DecodePrivate + Send + Sync,
{
    state: State,

    executor: E,

    _cipher: PhantomData<C>,
}

impl<C, E> MpcBlockCipher<C, E>
where
    C: BlockCipherCircuit,
    E: Memory + Execute + Decode + DecodePrivate + Send + Sync,
{
    /// Creates a new MPC block cipher.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the block cipher.
    /// * `executor` - The executor to use for the MPC.
    pub fn new(config: BlockCipherConfig, executor: E) -> Self {
        let private_execution_id = NestedId::new(&config.id)
            .append_string("private")
            .append_counter();
        let public_execution_id = NestedId::new(&config.id)
            .append_string("public")
            .append_counter();
        let j0_execution_id = NestedId::new(&config.id)
            .append_string("j0")
            .append_counter();

        Self {
            state: State {
                private_execution_id,
                public_execution_id,
                j0_execution_id,
                preprocessed_private: VecDeque::new(),
                preprocessed_public: VecDeque::new(),
                preprocessed_j0: VecDeque::new(),
                key_and_iv: None,
            },
            executor,
            _cipher: PhantomData,
        }
    }

    fn define_block(&mut self, vis: Visibility) -> BlockVars {
        let (id, msg) = match vis {
            Visibility::Private => {
                let id = self
                    .state
                    .private_execution_id
                    .increment_in_place()
                    .to_string();
                let msg = self
                    .executor
                    .new_private_input::<C::BLOCK>(&format!("{}/msg", &id))
                    .expect("message is not defined");
                (id, msg)
            }
            Visibility::Blind => {
                let id = self
                    .state
                    .private_execution_id
                    .increment_in_place()
                    .to_string();
                let msg = self
                    .executor
                    .new_blind_input::<C::BLOCK>(&format!("{}/msg", &id))
                    .expect("message is not defined");
                (id, msg)
            }
            Visibility::Public => {
                let id = self
                    .state
                    .public_execution_id
                    .increment_in_place()
                    .to_string();
                let msg = self
                    .executor
                    .new_public_input::<C::BLOCK>(&format!("{}/msg", &id))
                    .expect("message is not defined");
                (id, msg)
            }
        };

        let ciphertext = self
            .executor
            .new_output::<C::BLOCK>(&format!("{}/ciphertext", &id))
            .expect("message is not defined");

        BlockVars { msg, ciphertext }
    }

    fn define_counters(&mut self) -> CounterVars {
        let id = self.state.j0_execution_id.increment_in_place().to_string();

        let nonce = self
            .executor
            .new_public_input::<[u8; 8]>(&format!("{}/nonce", &id))
            .expect("nonce should be defined");
        let ctr = self
            .executor
            .new_public_input::<[u8; 4]>(&format!("{}/ctr", &id))
            .expect("counter should be defined");
        let ciphertext = self
            .executor
            .new_output::<C::BLOCK>(&format!("{}/ciphertext", &id))
            .expect("message is not defined");

        CounterVars {
            nonce,
            ctr,
            ciphertext,
        }
    }
}

#[async_trait]
impl<C, E> BlockCipher<C> for MpcBlockCipher<C, E>
where
    C: BlockCipherCircuit,
    E: Memory + Load + Execute + Decode + DecodePrivate + Send + Sync + Send,
{
    #[instrument(level = "trace", skip_all)]
    fn set_key(&mut self, key: ValueRef, iv: ValueRef) {
        let key_and_iv = EncodedKeyAndIv { key, iv };
        self.state.key_and_iv = Some(key_and_iv);
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess_blocks(
        &mut self,
        visibility: Visibility,
        count: usize,
    ) -> Result<(), BlockCipherError> {
        let key = self
            .state
            .key_and_iv
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?
            .key;

        for _ in 0..count {
            let vars = self.define_block(visibility);

            self.executor
                .load(
                    C::circuit(),
                    &[key.clone(), vars.msg.clone()],
                    &[vars.ciphertext.clone()],
                )
                .await?;

            match visibility {
                Visibility::Private | Visibility::Blind => {
                    self.state.preprocessed_private.push_back(vars)
                }
                Visibility::Public => self.state.preprocessed_public.push_back(vars),
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess_counters(&mut self, count: usize) -> Result<(), BlockCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .key_and_iv
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?;

        for _ in 0..count {
            let vars = self.define_counters();

            self.executor
                .load(
                    C::circuit_ctr(),
                    &[
                        key.clone(),
                        iv.clone(),
                        vars.nonce.clone(),
                        vars.ctr.clone(),
                    ],
                    &[vars.ciphertext.clone()],
                )
                .await?;

            self.state.preprocessed_j0.push_back(vars);
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_private(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError> {
        let len = plaintext.len();
        let block: C::BLOCK = plaintext
            .try_into()
            .map_err(|_| BlockCipherError::invalid_message_length::<C>(len))?;

        let key = self
            .state
            .key_and_iv
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?
            .key;

        let BlockVars { msg, ciphertext } =
            if let Some(vars) = self.state.preprocessed_private.pop_front() {
                vars
            } else {
                self.define_block(Visibility::Private)
            };

        self.executor.assign(&msg, block)?;

        self.executor
            .execute(C::circuit(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut outputs = self.executor.decode(&[ciphertext]).await?;

        let ciphertext: C::BLOCK = if let Ok(ciphertext) = outputs
            .pop()
            .expect("ciphertext should be present")
            .try_into()
        {
            ciphertext
        } else {
            panic!("ciphertext should be a block")
        };

        Ok(ciphertext.into())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_blind(&mut self) -> Result<Vec<u8>, BlockCipherError> {
        let key = self
            .state
            .key_and_iv
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?
            .key;

        let BlockVars { msg, ciphertext } =
            if let Some(vars) = self.state.preprocessed_private.pop_front() {
                vars
            } else {
                self.define_block(Visibility::Blind)
            };

        self.executor
            .execute(C::circuit(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut outputs = self.executor.decode(&[ciphertext]).await?;

        let ciphertext: C::BLOCK = if let Ok(ciphertext) = outputs
            .pop()
            .expect("ciphertext should be present")
            .try_into()
        {
            ciphertext
        } else {
            panic!("ciphertext should be a block")
        };

        Ok(ciphertext.into())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_share(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError> {
        let len = plaintext.len();
        let block: C::BLOCK = plaintext
            .try_into()
            .map_err(|_| BlockCipherError::invalid_message_length::<C>(len))?;

        let key = self
            .state
            .key_and_iv
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?
            .key;

        let BlockVars { msg, ciphertext } =
            if let Some(vars) = self.state.preprocessed_public.pop_front() {
                vars
            } else {
                self.define_block(Visibility::Public)
            };

        self.executor.assign(&msg, block)?;

        self.executor
            .execute(C::circuit(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut outputs = self.executor.decode_shared(&[ciphertext]).await?;

        let share: C::BLOCK =
            if let Ok(share) = outputs.pop().expect("share should be present").try_into() {
                share
            } else {
                panic!("share should be a block")
            };

        Ok(share.into())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn share_j0(&mut self, explicit_nonce: Vec<u8>) -> Result<Vec<u8>, BlockCipherError> {
        if explicit_nonce.len() != 8 {
            return Err(BlockCipherError::invalid_explicit_nonce_length::<C>(
                explicit_nonce.len(),
            ));
        }

        let EncodedKeyAndIv { key, iv } = self
            .state
            .key_and_iv
            .as_ref()
            .cloned()
            .ok_or_else(|| BlockCipherError::key_not_set())?;

        let CounterVars {
            nonce,
            ctr,
            ciphertext,
        } = if let Some(vars) = self.state.preprocessed_j0.pop_front() {
            vars
        } else {
            self.define_counters()
        };

        self.executor.assign(&nonce, explicit_nonce)?;
        self.executor.assign(&ctr, (1 as u32).to_be_bytes())?;

        self.executor
            .commit(&[key.clone(), iv.clone(), nonce.clone(), ctr.clone()])
            .await?;
        self.executor
            .execute(
                C::circuit_ctr(),
                &[key, iv, nonce, ctr],
                &[ciphertext.clone()],
            )
            .await?;

        let mut outputs = self.executor.decode_shared(&[ciphertext]).await?;

        let share: C::BLOCK =
            if let Ok(share) = outputs.pop().expect("share should be present").try_into() {
                share
            } else {
                panic!("share should be a block")
            };

        Ok(share.into())
    }
}
