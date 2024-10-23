//! An experimental Poseidon hash implementation over the BN256 curve with
//! custom parameters.
//!
//! This crate is only meant to be used for experimental purposes. The
//! parameters were not checked to be secure.

mod rate15_params;
mod rate1_params;
mod rate2_params;
mod spec;

use halo2_poseidon::poseidon::primitives::{ConstantLength, Hash};
use halo2_proofs::halo2curves::bn256;

pub use halo2_proofs::halo2curves::bn256::Fr as F;
pub use spec::{Spec1, Spec15, Spec2};

/// Hashes the provided input field elements and returns the digest.
///
/// # Panics
///
/// Panics if the provided input's length is not 15, 2, or 1 field elements.
pub fn hash(input: &[bn256::Fr]) -> bn256::Fr {

    match input.len() {

        15 =>            Hash::<bn256::Fr, spec::Spec15, ConstantLength<15>, 16, 15>::init()
                .hash(input.try_into().unwrap()),
       
        2 => Hash::<bn256::Fr, spec::Spec2, ConstantLength<2>, 3, 2>::init()
            .hash(input.try_into().unwrap()),
        1 => Hash::<bn256::Fr, spec::Spec1, ConstantLength<1>, 2, 1>::init()
            .hash(input.try_into().unwrap()),
        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod circom_compat {
    use tetris::{
        gadget::poseidon::{
            reference::{Permutation, Poseidon},
        },
        witness::field::Field,
    };
    use poseidon_bn254::{hash_with_domain, Fr};

    use super::*;

    use num_bigint::BigUint;
    use num_traits::Num;

    fn circom_rp(rate: usize) -> usize {
        [
            56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
        ]
        .get(rate - 1)
        .cloned()
        .unwrap()
    }

    #[test]
    fn scroll_circom() {
        let expect_decimal = |s: &str, e0: F| {
            let n = BigUint::from_str_radix(s, 10).unwrap();
            let e1 = F::from_uint(&n).unwrap();
            assert_eq!(e0, e1);
        };

        let r_f = 8;
        let cap = 1;
        let rate = 2;
        let r_p = circom_rp(rate);
        let poseidon: Poseidon<F> = Poseidon::generate(r_f, r_p, rate, cap, None);

        let inputs: Vec<F> = vec![0u64.into(), 3u64.into(), 4u64.into()];
        let start_at_zero_inputs: Vec<F> = vec![3u64.into(), 4u64.into()];

        let mut output = inputs.clone();
        poseidon.permute(&mut output);

        println!("inputs: {:?}", inputs);

        println!("tetris: {:?}", output[0]);

        let scroll_inputs = [Fr::from(3u64), Fr::from(4u64)];
        let domain = Fr::zero();
        let result = hash_with_domain(&scroll_inputs, domain);
        println!("bn254-domain: {:?}", result);

        let tlsnh2p = Hash::<bn256::Fr, spec::Spec2, ConstantLength<2>, 3, 2>::init()
            .hash(start_at_zero_inputs.try_into().unwrap());
        println!("tlsn/halo2-poseidon: {:?}", tlsnh2p);


        expect_decimal(
            "14763215145315200506921711489642608356394854266165572616578112107564877678998",
            output[0],
        );
        expect_decimal(
            "14763215145315200506921711489642608356394854266165572616578112107564877678998",
            tlsnh2p,
        );
    }
}
