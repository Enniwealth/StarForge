use crate::utils::{print as p, profiler::Timer};
use anyhow::Result;
use clap::Args;
use colored::*;
use std::path::PathBuf;

#[derive(Args)]
pub struct BenchmarkArgs {
    /// Benchmark WASM processing by reading a .wasm file and simulating operations
    #[arg(long)]
    pub wasm: Option<PathBuf>,
    /// Number of operations to simulate
    #[arg(long, default_value_t = 10_000)]
    pub operations: u64,
    /// Benchmark common CLI command paths (simulated)
    #[arg(long, default_value = "false")]
    pub cli_commands: bool,
    /// Output report format
    #[arg(long, value_parser = ["text", "json"], default_value = "text")]
    pub report: String,
}

pub fn handle(args: BenchmarkArgs) -> Result<()> {
    let timer = Timer::start();
    p::header("Benchmark");

    let mut wasm_bytes = None;
    if let Some(wasm) = &args.wasm {
        if !wasm.exists() {
            anyhow::bail!("WASM file not found: {}", wasm.display());
        }
        let bytes = std::fs::read(wasm)?;
        p::kv("WASM", &wasm.display().to_string());
        p::kv("WASM bytes", &bytes.len().to_string());
        wasm_bytes = Some(bytes);
    }

    if args.cli_commands {
        p::info("Simulating CLI hot paths (parse, config load, print)...");
        let _ = std::env::args().collect::<Vec<_>>();
    }

    if let Some(bytes) = wasm_bytes {
        p::info(&format!(
            "Simulating {} operations over WASM bytes…",
            args.operations.to_string().cyan()
        ));
        let mut acc: u64 = 0;
        for i in 0..args.operations {
            let idx = (i as usize) % bytes.len().max(1);
            acc = acc.wrapping_add(bytes.get(idx).copied().unwrap_or(0) as u64);
        }
        p::kv("Accumulator", &format!("0x{:x}", acc));
    }

    let elapsed = timer.elapsed();

    if args.report == "json" {
        let report = serde_json::json!({
            "wasm": args.wasm.as_ref().map(|p| p.display().to_string()),
            "operations": args.operations,
            "cli_commands": args.cli_commands,
            "elapsed_ms": elapsed.as_millis(),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        p::separator();
        p::kv_accent("Elapsed", &format!("{} ms", elapsed.as_millis()));
        p::info(&format!(
            "Run Criterion benchmarks with: {}",
            "cargo bench".cyan()
        ));
        p::separator();
    }

    Ok(())
}

