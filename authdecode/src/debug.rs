use halo2_proofs::dev::{cost::CircuitCost, CircuitLayout};
use pasta_curves::Eq;
use plotters::prelude::*;
use std::path::PathBuf;
use structopt::StructOpt;

use authdecode::halo2_backend::circuit::{AuthDecodeCircuit, K};

/// Utility to debug authdecode circuit
#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "Authdecode Debug")]
enum DebugCli {
    /// Draw the circuit layout
    Draw {
        /// Output diagram file path
        #[structopt(
            long,
            short,
            parse(from_os_str),
            default_value = "../target/halo2/authdecode-circuit-layout.png"
        )]
        out: PathBuf,
        /// Height of the circuit diagram
        #[structopt(long, short, default_value = "4096")]
        height: u32,
        /// Width of the circuit diagram
        #[structopt(long, short, default_value = "2048")]
        width: u32,
    },
    /// Measure the cost of the circuit
    Measure {
        /// Number of instance columns
        #[structopt(long, short, default_value = "3")]
        instance_size: usize,
    },
}

fn main() {
    let plaintext_salt = Default::default();
    let label_sum_salt = Default::default();
    let plaintext = Default::default();
    let deltas = [[Default::default(); 64]; 56];
    let circuit = AuthDecodeCircuit::new(plaintext, plaintext_salt, label_sum_salt, deltas);

    let command = DebugCli::from_args();
    match command {
        DebugCli::Draw {
            out,
            height: length,
            width,
        } => {
            draw_circuit(&circuit, &out, length, width);
        }
        DebugCli::Measure { instance_size } => {
            measure_circuit_cost(&circuit, instance_size);
        }
    }
}

fn measure_circuit_cost(circuit: &AuthDecodeCircuit, instance_size: usize) {
    println!("Measuring circuit cost...");
    let cost = CircuitCost::<Eq, AuthDecodeCircuit>::measure(K, circuit);
    println!("Circuit proof size: {:?}", cost.proof_size(instance_size));
    println!(
        "Circuit marginal proof size: {:?}",
        cost.marginal_proof_size()
    );
}

fn draw_circuit(circuit: &AuthDecodeCircuit, out: &PathBuf, length: u32, width: u32) {
    println!("Generating circuit diagram...");
    let drawing_area = BitMapBackend::new(out, (length, width)).into_drawing_area();
    drawing_area.fill(&WHITE).unwrap();
    let drawing_area = drawing_area
        .titled("Authdecode Circuit Layout", ("sans-serif", 60))
        .unwrap();
    CircuitLayout::default()
        .render(K, circuit, &drawing_area)
        .unwrap();
    println!("Circuit diagram generated!");
}
