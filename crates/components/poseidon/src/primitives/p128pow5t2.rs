use std::marker::PhantomData;


use poseidon_circuit::primitives::{permute, CachedSpec, ConstantLength, Hash, Spec};

use halon2curves::ff::FromUniformBytes;

use ff::{Field, FromUniformBytes};

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, generate_constants, ConstantLength, Mds, Spec},
    Hash, Pow5Chip, Pow5Config,
};

use halo2_proofs::halo2curves::bn256::Fr as F;

pub trait P128Pow5T2Constants: FromUniformBytes<64> + Ord {
    fn partial_rounds() -> usize {
        56
    }
    fn round_constants() -> Vec<[Self; 2]>;
    fn mds() -> Mds<Self, 2>;
    fn mds_inv() -> Mds<Self, 2>;
}

#[derive(Debug, Copy, Clone)]
pub struct P128Pow5T3<C> {
    _marker: PhantomData<C>,
}

impl<F: P128Pow5T3Constants> Spec<F, 2, 1> for P128Pow5T3<F> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        F::partial_rounds()
    }

    fn sbox(val: F) -> F {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[F; 2]>, Mds<F, 2>, Mds<F, 2>) {
        (F::round_constants(), F::mds(), F::mds_inv())
    }
}

#[cfg(any(test, feature = "test"))]
#[allow(unused_imports)]
mod tests {
    use std::marker::PhantomData;
    use halo2curves::ff::{FromUniformBytes, PrimeField};

    use super::*;    

    #[derive(Debug, Copy, Clone)]
    pub struct P128Pow5T3Gen<F: PrimeField, const SECURE_MDS: usize>(PhantomData<F>);

    type P128Pow5T3Pasta = super::P128Pow5T3<F>;

    impl<F: PrimeField, const SECURE_MDS: usize> P128Pow5T3Gen<F, SECURE_MDS> {
        pub fn new() -> Self {
            P128Pow5T3Gen(PhantomData::default())
        }
    }

    impl<F: FromUniformBytes<64> + Ord, const SECURE_MDS: usize> Spec<F, 2, 1>
        for P128Pow5T3Gen<F, SECURE_MDS>
    {
        fn full_rounds() -> usize {
            8
        }

        fn partial_rounds() -> usize {
            56
        }

        fn sbox(val: F) -> F {
            val.pow_vartime(&[5])
        }

        fn secure_mds() -> usize {
            SECURE_MDS
        }
    }

    impl CachedSpec<F, 2, 1> for P128Pow5T3Pasta {
        fn cached_round_constants() -> &'static [[F; 2]] {
            &F::ROUND_CONSTANTS
        }
        fn cached_mds() -> &'static Mds<F> {
            &F::MDS
        }
        fn cached_mds_inv() -> &'static Mds<F> {
            &F::MDS_INV
        }
    }

    #[test]
    fn verify_constants() {
        fn verify_constants_helper<F: FromUniformBytes<64> + Ord>(
            expected_round_constants: [[F; 2]; 64],
            expected_mds: [[F; 2]; 2],
            expected_mds_inv: [[F; 2]; 2],
        ) {
            let (round_constants, mds, mds_inv) = P128Pow5T3Gen::<F, 0>::constants();

            for (actual, expected) in round_constants
                .iter()
                .flatten()
                .zip(expected_round_constants.iter().flatten())
            {
                assert_eq!(actual, expected);
            }

            for (actual, expected) in mds.iter().flatten().zip(expected_mds.iter().flatten()) {
                assert_eq!(actual, expected);
            }

            for (actual, expected) in mds_inv
                .iter()
                .flatten()
                .zip(expected_mds_inv.iter().flatten())
            {
                assert_eq!(actual, expected);
            }
        }

        verify_constants_helper(F::ROUND_CONSTANTS, F::MDS, F::MDS_INV);
    }

    #[test]
    fn test_against_reference() {
        {

            let mut input = [
                F:from_raw([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                F::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            ];

            let expected_output = [
                F::from_raw([
                    0xaeb1_bc02_4aec_a456,
                    0xf7e6_9a71_d0b6_42a0,
                    0x94ef_b364_f966_240f,
                    0x2a52_6acd_0b64_b453,
                ]),
                F::from_raw([
                    0x012a_3e96_28e5_b82a,
                    0xdcd4_2e7f_bed9_dafe,
                    0x76ff_7dae_343d_5512,
                    0x13c5_d156_8b4a_a430,
                ]),
                F::from_raw([
                    0x3590_29a1_d34e_9ddd,
                    0xf7cf_dfe1_bda4_2c7b,
                    0x256f_cd59_7984_561a,
                    0x0a49_c868_c697_6544,
                ]),
            ];

//            permute::<F, P128Pow5T3Gen<F, 0>, 2, 1>(&mut input, &F::MDS, &F::ROUND_CONSTANTS);
  //          assert_eq!(input, expected_output);
        }

        /*        {
                    // <https://github.com/daira/pasta-hadeshash>, using parameters from
                    // `generate_parameters_grain.sage 1 0 255 3 8 56 0x40000000000000000000000000000000324698fc0994a8dd8c46eb2100000001`.
                    // The test vector is generated by `sage poseidonperm_x5_vesta_3.sage --rust`

                    let mut input = [
                        Fq::from_raw([
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                        ]),
                        Fq::from_raw([
                            0x0000_0000_0000_0001,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                        ]),
                        Fq::from_raw([
                            0x0000_0000_0000_0002,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                        ]),
                    ];

                    let expected_output = [
                        Fq::from_raw([
                            0x0eb0_8ea8_13be_be59,
                            0x4d43_d197_3dd3_36c6,
                            0xeddd_74f2_2f8f_2ff7,
                            0x315a_1f4c_db94_2f7c,
                        ]),
                        Fq::from_raw([
                            0xf9f1_26e6_1ea1_65f1,
                            0x413e_e0eb_7bbd_2198,
                            0x642a_dee0_dd13_aa48,
                            0x3be4_75f2_d764_2bde,
                        ]),
                        Fq::from_raw([
                            0x14d5_4237_2a7b_a0d9,
                            0x5019_bfd4_e042_3fa0,
                            0x117f_db24_20d8_ea60,
                            0x25ab_8aec_e953_728,
                        ]),
                    ];

                    permute::<Fq, P128Pow5T2Gen<Fq, 0>, 2, 1>(&mut input, &fq::MDS, &fq::ROUND_CONSTANTS);
                    assert_eq!(input, expected_output);
                }
        */
    }

}
