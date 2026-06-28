use crate::utils::{config, print as p, test_runner};
use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct TestArgs {
    /// Path to the compiled wasm
    #[arg(long)]
    pub wasm: PathBuf,

    /// Path to contract source for generation/coverage
    #[arg(long)]
    pub source: Option<PathBuf>,

    /// Collect coverage analysis (requires --source)
    #[arg(long, default_value = "false")]
    pub coverage: bool,

    /// Auto-generate test cases from source
    #[arg(long, default_value = "false")]
    pub generate: bool,

    /// Run tests in parallel
    #[arg(long, default_value = "false")]
    pub parallel: bool,

    /// Number of parallel workers
    #[arg(long, default_value = "4")]
    pub workers: usize,

    /// Output report format (html, json) — also generates dashboard
    #[arg(long)]
    pub report: Option<String>,
}

pub fn handle(args: TestArgs) -> Result<()> {
    config::validate_file_path(&args.wasm, Some("wasm"))?;
    if args.coverage && args.source.is_none() {
        anyhow::bail!("--coverage requires --source");
    }
    if args.generate && args.source.is_none() {
        anyhow::bail!("--generate requires --source");
    }

    p::header("Contract Test Runner");
    p::kv("Wasm", &args.wasm.display().to_string());
    p::kv("Coverage", if args.coverage { "yes" } else { "no" });
    p::kv("Generate", if args.generate { "yes" } else { "no" });
    p::kv("Parallel", if args.parallel { "yes" } else { "no" });
    if let Some(r) = &args.report {
        p::kv("Report", r);
    }

    let result = test_runner::run_contract_tests(
        &args.wasm,
        test_runner::TestOptions {
            coverage: args.coverage,
            report_format: args.report.clone(),
            parallel: args.parallel,
            generate: args.generate,
            source: args.source.clone(),
            workers: args.workers,
        },
    )?;

    println!();
    p::separator();
    p::kv_accent("SHA256", &result.sha256);
    p::kv("Wasm bytes", &result.size_bytes.to_string());
    p::kv("Cases executed", &result.cases_executed.to_string());
    p::kv("Failures", &result.failures.to_string());
    p::kv("Generated cases", &result.generated_cases.len().to_string());

    if let Some(cov) = &result.coverage {
        p::kv("Coverage", &format!("{:.1}%", cov.coverage_percent));
    }
    if let Some(path) = &result.report_path {
        p::kv("Report path", &path.display().to_string());
    }
    if let Some(path) = &result.dashboard_path {
        p::kv("Dashboard", &path.display().to_string());
    }

    if !result.failure_analysis.is_empty() {
        println!();
        p::header("Failure Analysis");
        for fa in &result.failure_analysis {
            println!("  {} [{}]: {}", fa.test_name, fa.category, fa.suggestion);
        }
    }

    p::separator();

    if result.failures > 0 {
        anyhow::bail!("Some contract tests failed");
    }

    p::success("All contract tests passed");
    Ok(())
}
