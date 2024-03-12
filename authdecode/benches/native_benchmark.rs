/// Used to statistically estimate authdecode protocol proving and verifying latency 

use std::{env, time::Duration};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num::BigUint;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use authdecode::{
    backend::halo2::{
        onetimesetup::OneTimeSetup, prover::{Prover as Halo2Prover, PK},
        verifier::{Verifier as Halo2Verifier, VK},
    },
    encodings::{Encoding, FullEncodings},
    prover::{
        prover::Prover, state::Checked, EncodingVerifier, EncodingVerifierError, InitData,
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

fn generate_prover_and_verifier(proving_key: PK, verification_key: VK) -> (
    Prover<Checked>,
    Verifier<CommitmentReceived>,
) {
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

    (prover, verifier)
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("authdecode_native_benchmark_group");
    group.measurement_time(Duration::from_secs(25));

    env::set_var("RAYON_NUM_THREADS", NUM_OF_THREADS);

    let params = OneTimeSetup::params();
    let proving_key = OneTimeSetup::proving_key(params.clone());
    let verification_key = OneTimeSetup::verification_key(params);

    group.bench_function(format!("authdecode_native_proof_generation_{}_thread", NUM_OF_THREADS), |b| {
        b.iter(|| {
            // Since we can't Clone provers, we generate a new prover for each
            // iteration. This should not add more than 1-2% runtime to the bench
            let (prover, _verifier) = generate_prover_and_verifier(proving_key.clone(), verification_key.clone());
            black_box(prover.prove().unwrap());
        })
    });

    // We cannot bench proof verification without running the proof generation.
    // To get the actual verification time, subtract from "generation+verification"
    // time the "generation only" time from the above bench.

    group.bench_function(
        format!("authdecode_native_proof_generation_and_verification_{}_thread", NUM_OF_THREADS),
        |b| {
            b.iter(|| {
                // Since we can't Clone prover, verifier, we generate a new prover and a new verifier
                // for each iteration. This should not add more than 1-2% runtime to the bench
                let (prover, verifier) =
                    generate_prover_and_verifier(proving_key.clone(), verification_key.clone());
                let (_, proofs) = prover.prove().unwrap();
                black_box(verifier.verify(proofs).unwrap());
            })
        },
    );

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
