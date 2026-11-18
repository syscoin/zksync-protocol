#![expect(warnings)]
#![feature(slice_from_ptr_range)]
#![feature(allocator_api)]

use clap::Parser;
use prover::{cs::one_row_compiler::CompiledCircuitArtifact, field::Mersenne31Field};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use zkos_verifier_generator::{generate_from_parts, generate_inlined_configured};

mod mersenne_wrapper;
use mersenne_wrapper::MersenneBoojumWrapper;

/// Returns formatted rust code with verifier and inline verifier files.
fn generate_verifier_files(circuit: &CompiledCircuitArtifact<Mersenne31Field>) -> (String, String) {
    let verifier = format_rust_code(&generate_from_parts(&circuit).to_string()).unwrap();

    let inlined_verifier = format_rust_code(
        &generate_inlined_configured::<MersenneBoojumWrapper>(circuit.clone()).to_string(),
    )
    .unwrap();

    (verifier, inlined_verifier)
}

/// Runs rustfmt to format the code.
fn format_rust_code(code: &str) -> Result<String, String> {
    // Spawn the `rustfmt` process
    let mut rustfmt = Command::new("rustfmt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn rustfmt: {}", e))?;

    // Write the Rust code to `rustfmt`'s stdin
    if let Some(mut stdin) = rustfmt.stdin.take() {
        stdin
            .write_all(code.as_bytes())
            .map_err(|e| format!("Failed to write to rustfmt stdin: {}", e))?;
    }

    // Wait for `rustfmt` to complete and collect the formatted code
    let output = rustfmt
        .wait_with_output()
        .map_err(|e| format!("Failed to read rustfmt output: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "rustfmt failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Convert the output to a String
    String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8 in rustfmt output: {}", e))
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(
        long,
        default_value = "wrapper/src/inner_verifiers/unified_reduced/imports"
    )]
    output_dir: String,
    #[arg(
        long,
        default_value = "wrapper/src/inner_verifiers/blake_delegation/imports"
    )]
    blake_output_dir: String,
}

fn write_verifier_files(
    directory: &Path,
    circuit: &CompiledCircuitArtifact<Mersenne31Field>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (layout, quotient) = generate_verifier_files(circuit);
    std::fs::write(directory.join("circuit_layout.rs"), layout)?;
    std::fs::write(directory.join("circuit_quotient.rs"), quotient)?;
    // Proof deserialization and the in-circuit verifier must agree on every column.
    std::fs::write(
        directory.join("circuit_layout.json"),
        serde_json::to_vec_pretty(circuit)?,
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let dummy_bytecode = vec![0u32; setups::unified_reduced_machine::MAX_ROM_SIZE / 4];
    let compiled_circuit = setups::unified_reduced_machine::get_circuit(&dummy_bytecode);
    write_verifier_files(Path::new(&cli.output_dir), &compiled_circuit)?;

    let blake_compiled_circuit =
        setups::blake2_with_compression::get_delegation_circuit().compiled_circuit;
    write_verifier_files(Path::new(&cli.blake_output_dir), &blake_compiled_circuit)
}
