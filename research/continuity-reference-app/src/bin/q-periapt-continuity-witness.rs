// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local Continuity witness operator; incoming network bytes cannot enroll devices.
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    native_device::clock,
    network::{self, Limits},
    witness::{EnrollmentRequest, EnrollmentTrust, Witness},
};
use std::{
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};
#[path = "../witness_credential_cli.rs"]
mod credential;
#[path = "../operator_io.rs"]
mod operator_io;
#[path = "../witness_policy_cli.rs"]
mod policy;
#[path = "../witness_replacement_cli.rs"]
mod replacement;
#[path = "../witness_root_cli.rs"]
mod root;
#[path = "../witness_roster_cli.rs"]
mod roster;
use operator_io::{export_directory, identifier, print, read, Result};

const USAGE: &str = "q-periapt-continuity-witness <init|prepare|pin|export|enroll|serve|replacement-prepare|replacement-commit|replacement-status|roster-prepare|roster-close|policy-prepare|policy-close|credential-prepare|credential-close> <absolute-host-db> <retained-base64url-identity>\nexport: <existing-empty-private-export-directory>\nenroll: <independently-approved-trust-json> <device-preparation-json>\nreplacement-prepare: <independently-approved-replacement-trust-json> <new-device-preparation-json> <existing-empty-private-export-directory>\nreplacement-commit: <same-replacement-trust-json> <same-device-preparation-json> <retained-decision-json>\nreplacement-status: <retained-decision-json>\nroster-prepare/roster-close: <independently-approved-roster-trust-json> <retained-roster-request-json>\npolicy-prepare/policy-close: <independently-approved-policy-trust-json> <retained-policy-preparation-json>\ncredential-prepare/credential-close: <independently-approved-credential-trust-json> <retained-credential-preparation-json> <issued-grant-json>\nserve: <numeric-IP:port>\nRetain all original files after errors. Enrollment and replacement are trusted local operator actions, separate from account login and device export.";
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let command = args.get(1).and_then(|value| value.to_str()).ok_or(USAGE)?;
    if command == "--help" && args.len() == 2 {
        println!("{USAGE}\n{}", root::USAGE);
        return Ok(());
    }
    if matches!(
        command,
        "root-plan"
            | "root-replan"
            | "root-freeze"
            | "root-bind"
            | "root-commit"
            | "root-status"
            | "root-close"
            | "root-plan-close"
    ) {
        return root::run(&args);
    }
    if matches!(command, "credential-prepare" | "credential-close") {
        return credential::run(&args);
    }
    if matches!(command, "policy-prepare" | "policy-close") {
        return policy::run(&args);
    }
    if matches!(command, "roster-prepare" | "roster-close") {
        return roster::run(&args);
    }
    if matches!(
        command,
        "replacement-prepare" | "replacement-commit" | "replacement-status"
    ) {
        return replacement::run(&args);
    }
    let count = match command {
        "init" | "prepare" | "pin" => 4,
        "enroll" => 6,
        "serve" | "export" => 5,
        _ => return Err(USAGE.into()),
    };
    if args.len() != count {
        return Err(USAGE.into());
    }
    let path = PathBuf::from(&args[2]);
    if !path.is_absolute() {
        return Err("Witness host path must be absolute".into());
    }
    let identity = identifier(&args[3])?;
    if command == "serve" {
        let address: SocketAddr = args[4]
            .to_str()
            .ok_or("Listen address is not UTF-8")?
            .parse()?;
        if address.ip().is_multicast()
            || matches!(address.ip(),std::net::IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err("Invalid witness listen address".into());
        }
        // Startup checks do not generate or repair anything.
        Witness::open(&path, identity)?.pin()?;
        return serve(path, identity, address);
    }
    let mut owner = if command == "init" {
        Witness::provision(&path, identity)?
    } else {
        Witness::open(&path, identity)?
    };
    match command {
        "init" | "prepare" => print(&owner.prepare()?),
        "pin" => print(&owner.pin()?),
        "export" => {
            let directory = Path::new(&args[4]);
            export_directory(directory)?;
            let pin = owner.pin()?;
            q_periapt_host_store::filesystem::publish_private_bytes(
                &directory.join("witness-pin.json"),
                &serde_json::to_vec(&pin)?,
            )?;
            print(&pin)
        }
        "enroll" => {
            let trust: EnrollmentTrust =
                serde_json::from_slice(&read(Path::new(&args[4]), 256 * 1024)?)?;
            let request: EnrollmentRequest =
                serde_json::from_slice(&read(Path::new(&args[5]), 8192)?)?;
            owner.enroll(&trust, &request, clock()?)?;
            print(
                &serde_json::json!({"enrollment":"Recorded","journal":trust.journal,"head":request.head}),
            )
        }
        _ => Err(USAGE.into()),
    }
}
fn serve(path: PathBuf, identity: [u8; 32], address: SocketAddr) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(address).await?;
        print(&serde_json::json!({"service":"Listening","carrier":"ContinuityAnchor/TCP","address":listener.local_addr()?.to_string()}))?;
        io::stdout().flush()?;
        let stop = sdk::Cancellation::default();
        let limits=Limits { queued:8, ..Limits::default() };
        let service = network::serve(listener, limits, stop.clone(), move |frame,run| {
            let result:Result<_> = (|| {
                run.check()?;
                let mut owner = Witness::open(&path, identity)?;
                owner.handle(frame, run, clock()?)
            })();
            result.map_err(|error| io::Error::other(error.to_string()))
        });
        tokio::pin!(service);
        let stats = tokio::select! {
            result=&mut service=>result?,
            signal=tokio::signal::ctrl_c()=>{
                stop.cancel();let result=service.await;signal?;result?
            }
        };
        print(&serde_json::json!({"service":"Stopped","stats":stats}))
    })
}
