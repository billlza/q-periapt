//! `pqt` — auditability & migration CLI for the PQ/T hybrid suite.

use clap::{Parser, Subcommand};
use pqt_cli::{cbom, findings_to_json, sbom, scan, Finding};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "pqt",
    version,
    about = "PQ/T hybrid suite: CBOM/SBOM + crypto migration scanner"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Emit a CycloneDX CBOM (crypto bill of materials) of the suite's assets.
    Cbom {
        /// Write to FILE instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Emit a CycloneDX SBOM derived from a Cargo.lock.
    Sbom {
        /// Path to Cargo.lock.
        #[arg(long, default_value = "Cargo.lock")]
        lock: PathBuf,
        /// Write to FILE instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Scan a path for legacy / quantum-vulnerable crypto and recommend migrations.
    /// Exits with code 2 if any high/critical finding is present (CI gate).
    Scan {
        /// Directory or file to scan.
        path: PathBuf,
        /// Emit JSON instead of a text report.
        #[arg(long)]
        json: bool,
    },
}

fn emit(value: &serde_json::Value, out: Option<&Path>) -> ExitCode {
    let text = serde_json::to_string_pretty(value).expect("serialize JSON");
    match out {
        Some(p) => match std::fs::write(p, text) {
            Ok(()) => {
                eprintln!("wrote {}", p.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: cannot write {}: {e}", p.display());
                ExitCode::FAILURE
            }
        },
        None => {
            println!("{text}");
            ExitCode::SUCCESS
        }
    }
}

fn print_findings(findings: &[Finding]) {
    let (mut crit, mut high, mut adv) = (0u32, 0u32, 0u32);
    for f in findings {
        match f.severity {
            "critical" => crit += 1,
            "high" => high += 1,
            _ => adv += 1,
        }
        println!(
            "{}:{}: [{}] {} ({})\n    -> {}",
            f.file, f.line, f.severity, f.category, f.token, f.recommendation
        );
    }
    if findings.is_empty() {
        println!("no legacy / quantum-vulnerable crypto found.");
    } else {
        println!(
            "\n{} finding(s): {crit} critical, {high} high, {adv} advisory",
            findings.len()
        );
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Cbom { out } => emit(&cbom(), out.as_deref()),
        Cmd::Sbom { lock, out } => match std::fs::read_to_string(&lock) {
            Ok(text) => emit(&sbom(&text), out.as_deref()),
            Err(e) => {
                eprintln!("error: cannot read {}: {e}", lock.display());
                ExitCode::FAILURE
            }
        },
        Cmd::Scan { path, json } => {
            let findings = scan(&path);
            if json {
                let text =
                    serde_json::to_string_pretty(&findings_to_json(&findings)).expect("serialize");
                println!("{text}");
            } else {
                print_findings(&findings);
            }
            if findings
                .iter()
                .any(|f| f.severity == "high" || f.severity == "critical")
            {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}
