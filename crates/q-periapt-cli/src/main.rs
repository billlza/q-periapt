//! `qperiapt` — auditability & migration CLI for the PQ/T hybrid suite.

use clap::{Parser, Subcommand};
use q_periapt_cli::{cbom, sbom, scan, scan_report_to_json, Finding, ScanError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(all(
    feature = "policy-store-migration",
    any(target_os = "macos", target_os = "linux")
))]
mod policy_store_upgrade;

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
    /// Reclaim one versioned unpublished attempt. Never pass a formal store path.
    /// Requires a publication-maintenance build and its supported native adapter.
    PublicationReclaim {
        /// Exact private control directory retained by the failed publication.
        attempt: PathBuf,
        /// Whole remaining payload entry budget, including its root (1..=4096).
        #[arg(long)]
        max_entries: usize,
        /// Maximum payload depth, including regular files (1..=64).
        #[arg(long)]
        max_depth: usize,
        /// Maximum sum of remaining file lengths (0..=4294967296).
        #[arg(long)]
        max_bytes: u64,
    },
    /// Offline format-2 to format-3 upgrade of an existing v1 host policy store.
    /// Requires a policy-store-migration build on macOS or Linux.
    PolicyStoreUpgrade {
        /// Existing private store. Missing storage is never created.
        path: PathBuf,
        /// Independently retained ML-DSA-65 root verification key (raw bytes).
        #[arg(long)]
        root: PathBuf,
        /// Independently retained exact 36-byte trusted state; never read it from the target store.
        #[arg(long)]
        expected_state: PathBuf,
    },
    /// Emit a CycloneDX CBOM (crypto bill of materials) of the suite's assets.
    Cbom {
        /// Catalogue the native owned SDK and configured TLS provider. Requires
        /// a build with --features sdk-cbom; never falls back to backend-only data.
        #[arg(long)]
        native_sdk: bool,
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
        Cmd::PublicationReclaim {
            attempt,
            max_entries,
            max_depth,
            max_bytes,
        } => {
            #[cfg(feature = "publication-maintenance")]
            {
                use q_periapt_host_store::filesystem::{
                    reclaim_private_publication, PublicationCleanupLimits,
                    PublicationCleanupOutcome,
                };
                let Some(name) = attempt.file_name().and_then(|name| name.to_str()) else {
                    eprintln!("error: publication-reclaim requires an original versioned control directory");
                    return ExitCode::FAILURE;
                };
                match reclaim_private_publication(
                    &attempt,
                    PublicationCleanupLimits {
                        entries: max_entries,
                        depth: max_depth,
                        bytes: max_bytes,
                    },
                ) {
                    Ok(outcome) => {
                        let report = match outcome {
                            PublicationCleanupOutcome::NoPayload => serde_json::json!({
                                "schema_version": 1, "operation": "private-publication-reclaim/v2",
                                "attempt": name, "outcome": "no-payload",
                            }),
                            PublicationCleanupOutcome::Reclaimed { entries, bytes } => {
                                serde_json::json!({
                                    "schema_version": 1, "operation": "private-publication-reclaim/v2",
                                    "attempt": name, "outcome": "reclaimed", "entries": entries, "bytes": bytes,
                                })
                            }
                        };
                        emit(&report, None)
                    }
                    Err(error) => {
                        eprintln!("error: publication reclamation failed: {error}; retain this control directory and its original records; an I/O failure may follow partial removal");
                        ExitCode::FAILURE
                    }
                }
            }
            #[cfg(not(feature = "publication-maintenance"))]
            {
                let _ = (attempt, max_entries, max_depth, max_bytes);
                eprintln!("error: publication-reclaim requires --features publication-maintenance");
                ExitCode::FAILURE
            }
        }
        Cmd::PolicyStoreUpgrade {
            path,
            root,
            expected_state,
        } => {
            #[cfg(all(
                feature = "policy-store-migration",
                any(target_os = "macos", target_os = "linux")
            ))]
            {
                match policy_store_upgrade::run(&path, &root, &expected_state) {
                    Ok(report) => emit(&report, None),
                    Err(error) => {
                        eprintln!("error: policy-store upgrade failed: {error}; preserve the file and retry only with the original independent trust and state; no runtime was returned");
                        ExitCode::FAILURE
                    }
                }
            }
            #[cfg(not(all(
                feature = "policy-store-migration",
                any(target_os = "macos", target_os = "linux")
            )))]
            {
                let _ = (path, root, expected_state);
                eprintln!("error: policy-store-upgrade requires --features policy-store-migration on macOS or Linux");
                ExitCode::FAILURE
            }
        }
        Cmd::Cbom {
            out,
            native_sdk: false,
        } => emit(&cbom(), out.as_deref()),
        Cmd::Cbom {
            out,
            native_sdk: true,
        } => {
            #[cfg(feature = "sdk-cbom")]
            match q_periapt_cli::native_sdk_cbom() {
                Ok(document) => emit(&document, out.as_deref()),
                Err(error) => {
                    eprintln!("error: cannot emit native SDK CBOM: {error}");
                    ExitCode::FAILURE
                }
            }
            #[cfg(not(feature = "sdk-cbom"))]
            {
                let _ = out;
                eprintln!("error: native SDK CBOM requires --features sdk-cbom");
                ExitCode::FAILURE
            }
        }
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
