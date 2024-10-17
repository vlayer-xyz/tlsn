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

//// testing with scroll poseidon hash impl as proxy for circom compat
use poseidon_bn254::{hash_code, hash_msg, hash_with_domain, Fr as sFr};
use std::array;


pub use halo2_proofs::halo2curves::bn256::Fr as F;
pub use spec::{Spec1, Spec15, Spec2};

/// Hashes the provided input field elements and returns the digest.
///
/// # Panics
///
/// Panics if the provided input's length is not 15, 2, or 1 field elements.
pub fn hash(input: &[bn256::Fr]) -> bn256::Fr {

    //// mac tests: for now this does nothing:
    let supposed_bytes = 45u128;
    let test = &array::from_fn::<_, 10, _>(|i| sFr::from(i as u64))[..];
    poseidon_bn254::hash_msg(test, Some(supposed_bytes));

    //// goal is to get the above to do the same as below and check if eq

    match input.len() {
        15 => Hash::<bn256::Fr, spec::Spec15, ConstantLength<15>, 16, 15>::init()
            .hash(input.try_into().unwrap()),
        2 => Hash::<bn256::Fr, spec::Spec2, ConstantLength<2>, 3, 2>::init()
            .hash(input.try_into().unwrap()),
        1 => Hash::<bn256::Fr, spec::Spec1, ConstantLength<1>, 2, 1>::init()
            .hash(input.try_into().unwrap()),
        _ => unimplemented!(),
    }
}
