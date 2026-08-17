//! `qperiapt` — auditability & migration CLI for the PQ/T hybrid suite.

use clap::{Parser, Subcommand};
use q_periapt_cli::{cbom, sbom, scan, scan_report_to_json, Finding, ScanError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "qperiapt",
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

fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn emit_to_writer(
    value: &serde_json::Value,
    out: Option<&Path>,
    stdout: &mut impl Write,
) -> ExitCode {
    let bytes = match canonical_json_bytes(value) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("error: cannot serialize JSON: {error}");
            return ExitCode::FAILURE;
        }
    };
    match out {
        Some(p) => match std::fs::write(p, bytes) {
            Ok(()) => {
                eprintln!("wrote {}", p.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: cannot write {}: {e}", p.display());
                ExitCode::FAILURE
            }
        },
        None => match stdout.write_all(&bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: cannot write stdout: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn emit(value: &serde_json::Value, out: Option<&Path>) -> ExitCode {
    emit_to_writer(value, out, &mut std::io::stdout().lock())
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

fn print_scan_errors(errors: &[ScanError]) {
    if errors.is_empty() {
        return;
    }
    eprintln!(
        "scan incomplete: {} path(s) could not be inspected",
        errors.len()
    );
    for e in errors {
        eprintln!("{}: [{}] {}", e.path, e.operation, e.message);
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
            let report = scan(&path);
            if json {
                let text =
                    serde_json::to_string_pretty(&scan_report_to_json(&report)).expect("serialize");
                println!("{text}");
            } else {
                print_findings(&report.findings);
                print_scan_errors(&report.errors);
            }
            if !report.errors.is_empty() {
                ExitCode::FAILURE
            } else if report
                .findings
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bom_bytes_are_exactly_newline_terminated() {
        let value = serde_json::json!({"bomFormat": "CycloneDX", "specVersion": "1.6"});
        assert_eq!(
            canonical_json_bytes(&value).expect("serialize canonical BOM fixture"),
            b"{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.6\"\n}\n"
        );
    }
}
