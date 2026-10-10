// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control-plane account association follows the first independently verified request.
use crate::{fixture, p, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

fn device(path: &Path, prefix: &str, certificate: &str, roster: &str) -> Result<p::VerifiedDevice> {
    let pin = p::AccountPin::new(
        fixture::array(path, &format!("{prefix}-account"))?,
        p::PublicKey::decode(&fixture::read(path, &format!("{prefix}-root"), 1985)?)?,
        p::RosterCheckpoint::from_trusted_state(
            u64::from_be_bytes(fixture::array(path, &format!("{prefix}-roster-version"))?),
            fixture::array(path, &format!("{prefix}-roster-digest"))?,
        )?,
        fixture::array(path, "family")?,
    )?;
    Ok(pin.verify_device(
        &fixture::read(path, certificate, 8192)?,
        &fixture::read(path, roster, 65536)?,
        fixture::now()?,
    )?)
}

pub(crate) fn associate(path: &Path, source: &Path, peer: &Path) -> Result<()> {
    assert!(!path.exists());
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let identity = p::AccountAuthorityIdentity::generate()?;
    let family = fixture::array(source, "family")?;
    let witness = fixture::array(source, "witness-id")?;
    let public = fixture::read(source, "witness-public", 1985)?;
    let mut registry = p::AccountAuthorityStore::provision(
        &path.join("authority.redb"),
        p::JournalKey::provision(&path.join("authority.key"))?,
        identity,
        family,
        p::AnchorPin::new(
            p::AnchorIdentity::from_trusted_state(witness)?,
            p::PublicKey::decode(&public)?,
        ),
    )?;
    // These records come from the issuer's actual verified request, never another identity's fixture.
    publish_private_bytes(
        &source.join("trusted-root"),
        &fixture::read(source, "enrollment-root", 1985)?,
    )?;
    let enrolled = device(source, "trusted", "grant-certificate", "grant-roster")?;
    let checkpoint = registry.associate(
        p::ApplicationAccountId::from_trusted_state([101; 32])?,
        &enrolled,
    )?;
    registry.associate(
        p::ApplicationAccountId::from_trusted_state([102; 32])?,
        &device(peer, "local", "local-certificate", "local-roster")?,
    )?;
    for (name, bytes) in [
        ("registry-id", identity.as_bytes().to_vec()),
        ("family", family.to_vec()),
        ("witness-id", witness.to_vec()),
        ("witness-public", public),
        ("application", checkpoint.application().as_bytes().to_vec()),
        ("account", checkpoint.account().to_vec()),
        ("revision", checkpoint.revision().to_be_bytes().to_vec()),
    ] {
        publish_private_bytes(&path.join(name), &bytes)?;
    }
    registry.close();
    Ok(())
}

pub(crate) fn export_public(
    source: &Path,
    base: &Path,
    registry: &Path,
    profile: &str,
    carrier: &str,
) -> Result<()> {
    let root = PathBuf::from(
        std::env::var_os("QPERIAPT_MANAGED_CONFIGURATION_EVIDENCE")
            .ok_or("explicit managed configuration evidence directory")?,
    );
    if !root.is_absolute() || !root.is_dir() {
        return Err("managed configuration evidence path".into());
    }
    let target = root.join(format!("{carrier}-{profile}"));
    fs::DirBuilder::new().mode(0o700).create(&target)?;
    for (name, input) in [
        ("request.bin", base.join("request")),
        ("replayed.bin", base.join("active-reopened")),
        ("root.bin", source.join("enrollment-root")),
        ("intent.bin", source.join("enrollment-intent")),
        ("genesis.bin", base.join("genesis")),
        ("session.bin", base.join("connected")),
        ("unknown.bin", base.join("uncertain")),
        ("acknowledged.bin", base.join("acknowledged")),
        ("after-traffic.bin", base.join("after-traffic.request")),
        ("effect.bin", base.join("effect-public")),
        ("registry-required.bin", base.join("registry-required")),
    ] {
        publish_private_bytes(&target.join(name), &fs::read(input)?)?;
    }
    for name in [
        "registry-id",
        "family",
        "witness-id",
        "witness-public",
        "application",
        "account",
        "revision",
    ] {
        publish_private_bytes(&target.join(name), &fixture::read(registry, name, 1985)?)?;
    }
    for name in [
        "request",
        "genesis",
        "missing",
        "active",
        "active-reopened",
        "registry-required",
        "connected",
        "uncertain",
        "acknowledged",
        "after-traffic",
    ] {
        for extension in ["stdout", "stderr"] {
            let name = format!("{name}.{extension}");
            publish_private_bytes(&target.join(&name), &fs::read(base.join(&name))?)?;
        }
    }
    let metadata = format!("{{\"schema_version\":1,\"language\":\"C\",\"profile\":\"{profile}\",\"carrier\":\"{carrier}\",\"release_claim_eligible\":false}}\n");
    publish_private_bytes(&target.join("manifest.json"), metadata.as_bytes())?;
    Ok(())
}
