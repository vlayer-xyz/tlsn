/// Used to manually test the performance of authdecode proving specifically
/// by printing out the latency taken to generate proof in the halo2 backend

use std::{env, time::Instant};

use num::BigUint;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use authdecode::{
    backend::halo2::{
        onetimesetup::OneTimeSetup, prover::Prover as Halo2Prover,
        verifier::Verifier as Halo2Verifier,
    },
    encodings::{Encoding, FullEncodings},
    prover::{
        prover::Prover, state::ProofCreated, EncodingVerifier, EncodingVerifierError, InitData,
    },
    utils::u8vec_to_boolvec,
    verifier::{state::CommitmentReceived, verifier::Verifier},
};

/// The size of plaintext in bytes;
const PLAINTEXT_SIZE: usize = 400;
/// Number of parallel threads
const NUM_OF_THREADS: &str = "1";

struct DummyEncodingsVerifier {}
impl EncodingVerifier for DummyEncodingsVerifier {
    fn init(&self, init_data: InitData) {}

    fn verify(&self, _encodings: &FullEncodings) -> Result<(), EncodingVerifierError> {
        Ok(())
    }
}

fn generate_prover_and_verifier() -> (
    Prover<ProofCreated>,
    Verifier<CommitmentReceived>,
    Vec<Vec<u8>>,
) {
    let params = OneTimeSetup::params();
    let proving_key = OneTimeSetup::proving_key(params.clone());
    let verification_key = OneTimeSetup::verification_key(params);
    let pair = (
        Halo2Prover::new(proving_key),
        Halo2Verifier::new(verification_key),
    );

    let prover = Prover::new(Box::new(pair.0));
    let verifier = Verifier::new(Box::new(pair.1));

    let mut rng = ChaCha12Rng::from_seed([0; 32]);

    // Generate random plaintext.
    let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
        .take(PLAINTEXT_SIZE)
        .collect();

    // Generate Verifier's full encodings for each bit of the plaintext.
    let full_encodings: Vec<[u128; 2]> = core::iter::repeat_with(|| rng.gen::<[u128; 2]>())
        .take(PLAINTEXT_SIZE * 8)
        .collect();
    let full_encodings = full_encodings
        .into_iter()
        .map(|pair| {
            [
                Encoding::new(BigUint::from(pair[0])),
                Encoding::new(BigUint::from(pair[1])),
            ]
        })
        .collect::<Vec<_>>();
    let full_encodings = FullEncodings::new(full_encodings);

    // Prover's active encodings.
    let active_encodings = full_encodings.encode(&u8vec_to_boolvec(&plaintext));

    let (prover, commitments) = prover.commit(vec![(plaintext, active_encodings)]).unwrap();

    let (verifier, verification_data) = verifier
        .receive_commitments(
            commitments,
            vec![full_encodings.clone()],
            InitData::new(vec![1u8; 100]),
        )
        .unwrap();

    let prover = prover
        .check(verification_data, DummyEncodingsVerifier {})
        .unwrap();

    let start = Instant::now();
    let (prover, proof_sets) = prover.prove().unwrap();
    let duration = start.elapsed();
    println!("Proving done in {:?}", duration);

    (prover, verifier, proof_sets)
}

fn prove_and_verify() {
    let (_, verifier, proof_sets) = generate_prover_and_verifier();
    let start = Instant::now();
    verifier.verify(proof_sets).unwrap();
    let duration = start.elapsed();
    println!("Verifying done in {:?}", duration);
}

fn main() {
    env::set_var("RAYON_NUM_THREADS", NUM_OF_THREADS);
    let _ = prove_and_verify();
}
