use crate::{MpcTlsError, TlsRole};
use mpz_circuits::{types::ValueType, Circuit, CircuitBuilder, Tracer};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeFutureTyped, MemoryExt, Vector, View, ViewExt,
};
use mpz_vm_core::{CallBuilder, Vm, VmExt};
use rand::{thread_rng, RngCore};
use std::sync::Arc;

/// Provides different decoding operations.
///
/// Supports decoding for the leader only by calling [`Decode::private`] or decoding additive
/// shares for both parties by calling [`Decode::shared`].
pub(crate) struct Decode {
    role: TlsRole,
    value: Vector<U8>,
    otp_0: Vector<U8>,
    otp_1: Vector<U8>,
    len: usize,
}

impl Decode {
    /// Creates a new decoding instance.
    ///
    /// # Arguments
    ///
    /// * `role` - The role, either leader or follower.
    /// * `value` - The value to decode.
    pub(crate) fn new<V>(vm: &mut V, role: TlsRole, value: Vector<U8>) -> Result<Self, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let len = value.len();
        let otp_0: Vector<U8> = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
        let otp_1: Vector<U8> = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
        let decode = Self {
            role,
            value,
            otp_0,
            otp_1,
            len,
        };

        Ok(decode)
    }
}

impl Decode {
    /// Creates a [`OneTimePadPrivate`], which supports decoding for the leader only.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    pub(crate) fn private<V>(self, vm: &mut V) -> Result<OneTimePadPrivate, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let otp_value = match self.role {
            TlsRole::Leader => {
                let mut rng = thread_rng();
                let mut otp_value = vec![0_u8; self.len];
                rng.fill_bytes(&mut otp_value);

                vm.mark_private(self.otp_0).map_err(MpcTlsError::vm)?;
                vm.assign(self.otp_0, otp_value.clone())
                    .map_err(MpcTlsError::vm)?;
                Some(otp_value)
            }
            TlsRole::Follower => {
                vm.mark_blind(self.otp_0).map_err(MpcTlsError::vm)?;
                None
            }
        };
        vm.commit(self.otp_0).map_err(MpcTlsError::vm)?;

        let otp_circuit = build_otp(self.len);
        let call = CallBuilder::new(otp_circuit)
            .arg(self.value)
            .arg(self.otp_0)
            .build()
            .map_err(MpcTlsError::vm)?;

        let output: Vector<U8> = vm.call(call).map_err(MpcTlsError::vm)?;
        let output = vm.decode(output).map_err(MpcTlsError::vm)?;

        let otp = OneTimePadPrivate {
            role: self.role,
            value: output,
            otp: otp_value,
        };

        Ok(otp)
    }

    /// Creates a [`OneTimePadShared`], which supports decoding additive shares of the inner value
    /// for leader and follower.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    pub(crate) fn shared<V>(self, vm: &mut V) -> Result<OneTimePadShared, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let mut rng = thread_rng();
        let mut otp_value = vec![0_u8; self.len];
        rng.fill_bytes(&mut otp_value);

        let otp_0 = self.otp_0;
        let otp_1 = self.otp_1;

        if let TlsRole::Leader = self.role {
            vm.mark_private(otp_0).map_err(MpcTlsError::vm)?;
            vm.mark_blind(otp_1).map_err(MpcTlsError::vm)?;
            vm.assign(otp_0, otp_value.clone())
                .map_err(MpcTlsError::vm)?;
        } else {
            vm.mark_private(otp_1).map_err(MpcTlsError::vm)?;
            vm.mark_blind(otp_0).map_err(MpcTlsError::vm)?;
            vm.assign(otp_1, otp_value.clone())
                .map_err(MpcTlsError::vm)?;
        }

        vm.commit(otp_0).map_err(MpcTlsError::vm)?;
        vm.commit(otp_1).map_err(MpcTlsError::vm)?;

        let otp_circuit = build_otp_shared(self.len);
        let call = CallBuilder::new(otp_circuit)
            .arg(self.value)
            .arg(otp_0)
            .arg(otp_1)
            .build()
            .map_err(MpcTlsError::vm)?;

        let output: Vector<U8> = vm.call(call).map_err(MpcTlsError::vm)?;
        let output = vm.decode(output).map_err(MpcTlsError::vm)?;

        let otp = OneTimePadShared {
            role: self.role,
            value: output,
            otp: otp_value,
        };

        Ok(otp)
    }
}

/// Supports private decoding.
pub(crate) struct OneTimePadPrivate {
    role: TlsRole,
    value: DecodeFutureTyped<BitVec, Vec<u8>>,
    otp: Option<Vec<u8>>,
}

impl OneTimePadPrivate {
    /// Decodes the inner value for the leader.
    pub(crate) async fn decode(self) -> Result<Option<Vec<u8>>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode)?;
        match self.role {
            TlsRole::Leader => {
                let otp = self.otp.expect("Otp should be set for leader");
                let out = value
                    .into_iter()
                    .zip(otp.into_iter())
                    .map(|(v, o)| v ^ o)
                    .collect();
                Ok(Some(out))
            }
            TlsRole::Follower => Ok(None),
        }
    }
}

/// Supports decoding into additive shares.
pub(crate) struct OneTimePadShared {
    role: TlsRole,
    value: DecodeFutureTyped<BitVec, Vec<u8>>,
    otp: Vec<u8>,
}

impl OneTimePadShared {
    /// Decodes the inner value as additive shares for leader and follower.
    pub(crate) async fn decode(self) -> Result<Vec<u8>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode)?;
        match self.role {
            TlsRole::Leader => {
                let value = value
                    .into_iter()
                    .zip(self.otp.into_iter())
                    .map(|(v, o)| v ^ o)
                    .collect();
                Ok(value)
            }
            TlsRole::Follower => Ok(self.otp),
        }
    }
}

/// Builds a circuit for applying one-time pads to the provided values.
pub(crate) fn build_otp(len: usize) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    let input = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp = builder.add_input_by_type(ValueType::new_array::<u8>(len));

    let input = Tracer::new(builder.state(), input);
    let otp = Tracer::new(builder.state(), otp);
    let masked = input ^ otp;
    builder.add_output(masked);

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}

/// Builds a circuit for applying one-time pads to secret-share the provided values.
pub(crate) fn build_otp_shared(len: usize) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    let input = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp_0 = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp_1 = builder.add_input_by_type(ValueType::new_array::<u8>(len));

    let input = Tracer::new(builder.state(), input);
    let otp_0 = Tracer::new(builder.state(), otp_0);
    let otp_1 = Tracer::new(builder.state(), otp_1);
    let masked = input ^ otp_0 ^ otp_1;
    builder.add_output(masked);

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mpz_circuits::{ops::WrappingAdd, Circuit, CircuitBuilder};
    use mpz_common::executor::test_st_executor;
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
    use mpz_memory_core::{
        binary::U8, correlated::Delta, FromRaw, MemoryExt, ToRaw, Vector, ViewExt,
    };
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_vm_core::{CallBuilder, Execute, VmExt};
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{decode::Decode, TlsRole};

    #[tokio::test]
    async fn test_decode_private() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm();

        let circ = build_adder();
        let circ = Arc::new(circ);

        let a = 128_u8;
        let b = 127_u8;

        let a_ref_gen: U8 = gen.alloc().unwrap();
        let b_ref_gen: U8 = gen.alloc().unwrap();

        let a_ref_ev: U8 = ev.alloc().unwrap();
        let b_ref_ev: U8 = ev.alloc().unwrap();

        let call_gen = CallBuilder::new(circ.clone())
            .arg(a_ref_gen)
            .arg(b_ref_gen)
            .build()
            .unwrap();
        let call_ev = CallBuilder::new(circ)
            .arg(a_ref_ev)
            .arg(b_ref_ev)
            .build()
            .unwrap();

        let output_gen: U8 = gen.call(call_gen).unwrap();
        let output_ev: U8 = ev.call(call_ev).unwrap();

        let output_gen: Vector<U8> = Vector::from_raw(output_gen.to_raw());
        let output_ev: Vector<U8> = Vector::from_raw(output_ev.to_raw());

        let output_gen = Decode::new(&mut gen, TlsRole::Leader, output_gen)
            .unwrap()
            .private(&mut gen)
            .unwrap();
        let output_ev = Decode::new(&mut ev, TlsRole::Follower, output_ev)
            .unwrap()
            .private(&mut ev)
            .unwrap();

        gen.mark_private(a_ref_gen).unwrap();
        gen.mark_blind(b_ref_gen).unwrap();
        gen.assign(a_ref_gen, a).unwrap();

        ev.mark_private(b_ref_ev).unwrap();
        ev.mark_blind(a_ref_ev).unwrap();
        ev.assign(b_ref_ev, b).unwrap();

        gen.commit(a_ref_gen).unwrap();
        gen.commit(b_ref_gen).unwrap();

        ev.commit(a_ref_ev).unwrap();
        ev.commit(b_ref_ev).unwrap();

        let (output_gen, output_ev) = tokio::try_join!(
            async {
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                output_gen.decode().await
            },
            async {
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                output_ev.decode().await
            }
        )
        .unwrap();

        assert!(output_gen.is_some());
        assert!(output_ev.is_none());

        let output_gen = output_gen.unwrap().pop().unwrap();
        assert_eq!(output_gen, a + b);
    }

    #[tokio::test]
    async fn test_decode_shared() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm();

        let circ = build_adder();
        let circ = Arc::new(circ);

        let a = 128_u8;
        let b = 127_u8;

        let a_ref_gen: U8 = gen.alloc().unwrap();
        let b_ref_gen: U8 = gen.alloc().unwrap();

        let a_ref_ev: U8 = ev.alloc().unwrap();
        let b_ref_ev: U8 = ev.alloc().unwrap();

        let call_gen = CallBuilder::new(circ.clone())
            .arg(a_ref_gen)
            .arg(b_ref_gen)
            .build()
            .unwrap();
        let call_ev = CallBuilder::new(circ)
            .arg(a_ref_ev)
            .arg(b_ref_ev)
            .build()
            .unwrap();

        let output_gen: U8 = gen.call(call_gen).unwrap();
        let output_ev: U8 = ev.call(call_ev).unwrap();

        let output_gen: Vector<U8> = Vector::from_raw(output_gen.to_raw());
        let output_ev: Vector<U8> = Vector::from_raw(output_ev.to_raw());

        let output_gen = Decode::new(&mut gen, TlsRole::Leader, output_gen)
            .unwrap()
            .shared(&mut gen)
            .unwrap();
        let output_ev = Decode::new(&mut ev, TlsRole::Follower, output_ev)
            .unwrap()
            .shared(&mut ev)
            .unwrap();

        gen.mark_private(a_ref_gen).unwrap();
        gen.mark_blind(b_ref_gen).unwrap();
        gen.assign(a_ref_gen, a).unwrap();

        ev.mark_private(b_ref_ev).unwrap();
        ev.mark_blind(a_ref_ev).unwrap();
        ev.assign(b_ref_ev, b).unwrap();

        gen.commit(a_ref_gen).unwrap();
        gen.commit(b_ref_gen).unwrap();

        ev.commit(a_ref_ev).unwrap();
        ev.commit(b_ref_ev).unwrap();

        let (mut output_gen, mut output_ev) = tokio::try_join!(
            async {
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                output_gen.decode().await
            },
            async {
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                output_ev.decode().await
            }
        )
        .unwrap();

        let output_gen = output_gen.pop().unwrap();
        let output_ev = output_ev.pop().unwrap();

        assert_eq!(output_gen + output_ev, a + b);
    }

    fn mock_vm() -> (Generator<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }

    fn build_adder() -> Circuit {
        let builder = CircuitBuilder::new();

        let a = builder.add_input::<u8>();
        let b = builder.add_input::<u8>();

        let c = a.wrapping_add(b);

        builder.add_output(c);

        builder.build().unwrap()
    }
}
