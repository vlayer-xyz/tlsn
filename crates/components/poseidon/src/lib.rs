
mod primitives;

use halo2_proofs::halo2curves::bn256;
use halo2_proofs::halo2curves::bn256::Fr as F;


fn backend_hash<S, const WIDTH: usize, const RATE: usize, const L: usize>(
    name: &str,
) where
    S: Spec<F, WIDTH, RATE> + Copy + Clone,
{
 
}
pub fn hash(input: &[bn256::Fr]) -> bn256::Fr {
    match input.len() {
        15 => backend_hash::<P128Pow5T16Gen<bn256::Fr>, 16, 15, 15>("WIDTH = 16, RATE = 15"),
        2 => F::from(0),
        1 => F::from(0),
        _ => unimplemented!(),
    }

}

