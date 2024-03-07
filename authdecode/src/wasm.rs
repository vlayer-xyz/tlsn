use std::env;

use num::BigUint;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use wasm_bindgen::prelude::*;

use crate::{backend::halo2::{onetimesetup::OneTimeSetup, prover::Prover as Halo2Prover, verifier::Verifier as Halo2Verifier}, encodings::{Encoding, FullEncodings}, prover::{prover::Prover, state::ProofCreated, InitData}, utils::u8vec_to_boolvec, verifier::{state::CommitmentReceived, verifier::Verifier}};

pub use wasm_bindgen_rayon::init_thread_pool;

extern crate console_error_panic_hook;

/// The size of plaintext in bytes;
const PLAINTEXT_SIZE: usize = 400;

// A macro to provide `println!(..)`-style syntax for `console.log` logging.
macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

struct DummyEncodingsVerifier {}
impl crate::prover::EncodingVerifier for DummyEncodingsVerifier {
    fn init(&self, init_data: InitData) {}

    fn verify(
        &self,
        _encodings: &FullEncodings,
    ) -> Result<(), crate::prover::EncodingVerifierError> {
        Ok(())
    }
}

fn create_prover_and_verifer() -> (Prover<ProofCreated>, Verifier<CommitmentReceived>, Vec<Vec<u8>>) {
     // benchmarking single threaded halo2
     env::set_var("RAYON_NUM_THREADS", "1");

    log!("Setting up...");
    let params = OneTimeSetup::params();
    let proving_key = OneTimeSetup::proving_key(params.clone());
    let verification_key = OneTimeSetup::verification_key(params);
    let pair = (Halo2Prover::new(proving_key), Halo2Verifier::new(verification_key));

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

    log!("Prover committing plaintexts and encoding sum...");
    let (prover, commitments) = prover.commit(vec![(plaintext, active_encodings)]).unwrap();

    log!("Verifier sending full encodings...");
    let (verifier, verification_data) = verifier
        .receive_commitments(
            commitments,
            vec![full_encodings.clone()],
            InitData::new(vec![1u8; 100]),
        )
        .unwrap();

    log!("Prover checking full encodings...");
    let prover = prover
        .check(verification_data, DummyEncodingsVerifier {})
        .unwrap();

    log!("Prover generating proofs...");
    let (prover, proof_sets) = prover.prove().unwrap();

    (prover, verifier, proof_sets)
}

#[wasm_bindgen]
pub fn prove() {
    let _ = create_prover_and_verifer();
}

#[wasm_bindgen]
pub fn verify() {
    let (_, verifier, proof_sets) = create_prover_and_verifer();
    log!("Verifier verifying proofs...");
    verifier.verify(proof_sets).unwrap();
}
