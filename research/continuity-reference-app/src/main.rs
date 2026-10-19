// SPDX-License-Identifier: Apache-2.0 OR MIT
mod http;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use error::Error;
use q_periapt_continuity_reference_app::{auth, error, store};
use std::{
    future::IntoFuture,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use webauthn_rs::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() < 4 || args.len() > 5 {
        return Err("Usage: q-periapt-continuity-reference-app <init|serve|enable-enrollment|enable-reapproval> <absolute-database-path> <http://localhost:port> [base64url-policy-family]".into());
    }
    let command = args[1].to_str().ok_or("Invalid command")?;
    if args.len() != if command == "enable-enrollment" { 5 } else { 4 } {
        return Err("Only enable-enrollment requires an explicit policy family".into());
    }
    let path = PathBuf::from(&args[2]);
    if !path.is_absolute() {
        return Err("Database path must be absolute beneath an existing private directory".into());
    }
    let origin = Url::parse(args[3].to_str().ok_or("Invalid origin")?)?;
    if origin.scheme() != "http"
        || origin.host_str() != Some("localhost")
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err("Initial local profile requires an exact http://localhost:port origin".into());
    }
    let port = origin
        .port()
        .ok_or("An explicit nondefault port is required")?;
    if port == 0 {
        return Err("Port zero is not a stable relying-party origin".into());
    }
    let canonical_origin = origin.origin().ascii_serialization();
    match command {
        "init" => {
            let _store = store::Store::provision(&path, &canonical_origin)?;
            println!("Account database initialized. Run serve with the same path and origin.");
        }
        "serve" => {
            let store = store::Store::open(&path, &canonical_origin)?;
            let webauthn = WebauthnBuilder::new("localhost", &origin)?
                .rp_name("Q-Periapt reference account")
                .build()?;
            let state = http::Shared::new(
                auth::Service::new(webauthn, store),
                canonical_origin.clone(),
                format!("localhost:{port}"),
            );
            let listener =
                tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
                    .await?;
            println!("Reference account application: {canonical_origin}");
            tokio::select! {
                result = axum::serve(listener, http::router(state)).into_future() => {
                    result.map_err(|e| Error::internal("HTTP service", e))?;
                }
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(|e| Error::internal("shutdown signal", e))?;
                }
            }
        }
        "enable-enrollment" => {
            let family: [u8; 32] = URL_SAFE_NO_PAD.decode(args[4].to_str().ok_or("Invalid policy family")?)?
                .try_into().map_err(|_| "Policy family must contain exactly 32 bytes")?;
            let mut store = store::Store::open(&path, &canonical_origin)?;
            store.enable_enrollment(family)?;
            println!("Enrollment schema enabled; existing accounts and credentials retained.");
        }
        "enable-reapproval" => {
            let mut store = store::Store::open(&path, &canonical_origin)?;
            store.enable_enrollment_reapproval()?;
            println!("Reapproval schema enabled; original enrollment decisions retained.");
        }
        _ => {
            return Err(
                "Command must be init, serve, enable-enrollment or enable-reapproval; opening never creates a missing database".into(),
            )
        }
    }
    Ok(())
}
