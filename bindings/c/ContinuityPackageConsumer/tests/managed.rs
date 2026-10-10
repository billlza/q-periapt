// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual installed C owners: managed admission, retained delivery and closure.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "common/receiver_process.rs"]
mod receiver_process;
#[path = "common/witness.rs"]
mod witness;
use q_periapt_continuity_identity_candidate as p;
use std::{
    ffi::OsString,
    fs, io,
    net::{SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PAYLOAD: &[u8] = b"persisted before process exit";

fn verified_device(path: &Path) -> Result<p::VerifiedDevice> {
    let pin = p::AccountPin::new(
        fixture::array(path, "local-account")?,
        p::PublicKey::decode(&fixture::read(path, "local-root", 8192)?)?,
        p::RosterCheckpoint::from_trusted_state(
            u64::from_be_bytes(fixture::array(path, "local-roster-version")?),
            fixture::array(path, "local-roster-digest")?,
        )?,
        fixture::array(path, "family")?,
    )?;
    Ok(pin.verify_device(
        &fixture::read(path, "local-certificate", 8192)?,
        &fixture::read(path, "local-roster", 8192)?,
        fixture::now()?,
    )?)
}

fn registry(path: &Path, local: &Path, peer: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let identity = p::AccountAuthorityIdentity::generate()?;
    let family = fixture::array(local, "family")?;
    let witness = fixture::array(local, "witness-id")?;
    let public = fixture::read(local, "witness-public", 1985)?;
    let mut owner = p::AccountAuthorityStore::provision(
        &path.join("authority.redb"),
        p::JournalKey::provision(&path.join("authority.key"))?,
        identity,
        family,
        p::AnchorPin::new(
            p::AnchorIdentity::from_trusted_state(witness)?,
            p::PublicKey::decode(&public)?,
        ),
    )?;
    let checkpoint = owner.associate(
        p::ApplicationAccountId::from_trusted_state([101; 32])?,
        &verified_device(local)?,
    )?;
    owner.associate(
        p::ApplicationAccountId::from_trusted_state([102; 32])?,
        &verified_device(peer)?,
    )?;
    for (name, value) in [
        ("registry-id", identity.as_bytes().to_vec()),
        ("family", family.to_vec()),
        ("witness-id", witness.to_vec()),
        ("witness-public", public),
        ("application", checkpoint.application().as_bytes().to_vec()),
        ("account", checkpoint.account().to_vec()),
        ("revision", checkpoint.revision().to_be_bytes().to_vec()),
    ] {
        fixture::store(path, name, &value)?;
    }
    owner.close();
    Ok(())
}

struct Case<'a> {
    root: &'a Path,
    local: &'a Path,
    peer: &'a Path,
    registry: PathBuf,
    managed: PathBuf,
    receiver: PathBuf,
    witness: SocketAddr,
}
impl Case<'_> {
    fn run(&self, label: &str, mode: &str, registry: &Path, tail: &[String]) -> Result<String> {
        let stdout = self.root.join(format!("managed-{label}.stdout"));
        let stderr = self.root.join(format!("managed-{label}.stderr"));
        let output = |path| {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        };
        let mut child = fixture::OwnedChild(
            Command::new(&self.managed)
                .arg(mode)
                .arg(self.local)
                .arg(registry)
                .arg(self.witness.to_string())
                .args(tail)
                .stdout(Stdio::from(output(&stdout)?))
                .stderr(Stdio::from(output(&stderr)?))
                .spawn()?,
        );
        let status = fixture::wait(&mut child)?;
        let error = fs::read_to_string(stderr)?;
        if !status.success() || !error.is_empty() {
            return Err(format!("managed C {label}: {status}; {error}").into());
        }
        Ok(String::from_utf8(fixture::read(
            self.root,
            &format!("managed-{label}.stdout"),
            65536,
        )?)?)
    }
    fn server(
        &self,
        label: &str,
        mode: &str,
        session: Option<&str>,
    ) -> Result<(receiver_process::Server, SocketAddr)> {
        let mut args: Vec<OsString> = vec!["--witness".into(), self.witness.to_string().into()];
        if let Some(session) = session {
            args.extend(["--session".into(), session.into()]);
        }
        args.extend(["serve".into(), self.peer.as_os_str().into(), mode.into()]);
        if mode == "rekey" {
            args.push(session.ok_or("rekey session required")?.into());
        }
        receiver_process::start_selected(&self.receiver, None, self.root, label, &args)
    }
}
fn identifier(text: &str) -> Result<[u8; 32]> {
    let text = text.strip_suffix('\n').ok_or("identifier newline")?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("identifier encoding".into());
    }
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *out = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(result)
}
fn executable(name: &str) -> Result<PathBuf> {
    let value = PathBuf::from(std::env::var_os(name).ok_or("installed executable not selected")?);
    if !value.is_absolute() || !value.is_file() {
        return Err("installed executable path".into());
    }
    Ok(value)
}

#[test]
fn managed_c_session_preserves_original_delivery_and_revokes_cached_owners() -> Result<()> {
    let mut witness = witness::Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let root = setup.initiator.parent().ok_or("fixture parent")?;
    let case = Case {
        root,
        local: &setup.initiator,
        peer: &setup.responder,
        registry: root.join("registry"),
        managed: executable("QPC_MANAGED_CLIENT")?,
        receiver: executable("QPERIAPT_C_OWNER_CLIENT")?,
        witness: witness.configured.address,
    };
    registry(&case.registry, case.local, case.peer)?;
    let wrong = root.join("other-registry");
    registry(&wrong, case.local, case.peer)?;
    let (server, address) = case.server("bootstrap", "bootstrap", None)?;
    let session = identifier(&case.run(
        "connect",
        "connect",
        &case.registry,
        &[
            address.to_string(),
            fixture::hex(p::InitiationId::generate()?.as_bytes()),
        ],
    )?)?;
    let session_text = fixture::hex(&session);
    assert_eq!(
        receiver_process::finish(server, 0)?,
        format!("served:1:0:0:0\n{session_text}\n{}\n", "0".repeat(64))
    );
    let message = identifier(&case.run(
        "next",
        "next",
        &case.registry,
        std::slice::from_ref(&session_text),
    )?)?;
    let message_text = fixture::hex(&message);
    assert_eq!(
        case.run(
            "wrong-registry",
            "reject",
            &wrong,
            std::slice::from_ref(&session_text)
        )?,
        "managed-rejected:211\n"
    );
    witness.arm(2)?;
    assert_eq!(
        case.run(
            "bad-witness",
            "bad-signature",
            &case.registry,
            std::slice::from_ref(&session_text)
        )?,
        "managed-rejected:218\n"
    );
    let (server, address) = case.server("unknown", "crash-after", Some(&session_text))?;
    assert_eq!(
        case.run(
            "uncertain",
            "uncertain",
            &case.registry,
            &[
                session_text.clone(),
                message_text.clone(),
                address.to_string()
            ]
        )?,
        "managed-delivery-unknown:2\n"
    );
    receiver_process::finish(server, 77)?;
    fixture::effect(
        case.peer,
        session,
        p::MessageId::from_trusted_state(message)?,
        PAYLOAD,
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    assert_eq!(
        case.run(
            "closed",
            "closed",
            &case.registry,
            &[
                session_text.clone(),
                message_text.clone(),
                listener.local_addr()?.to_string()
            ]
        )?,
        "managed-closed query=202 send=1202 reopened_registry_old_owner=1202 original_status=2\n"
    );
    assert!(matches!(listener.accept(), Err(error) if error.kind()==io::ErrorKind::WouldBlock));
    let (server, address) = case.server("resend", "message", Some(&session_text))?;
    assert_eq!(
        case.run(
            "resend",
            "send",
            &case.registry,
            &[
                session_text.clone(),
                message_text.clone(),
                address.to_string()
            ]
        )?,
        "managed-consumed:3\n"
    );
    // The first process exited after the host effect and before SDK consumption
    // commit. This is the first SDK-confirmed receive; host deduplication must
    // still keep created=0 when the callback runs again for the original ID.
    let delivered = receiver_process::finish(server, 0)?;
    assert_eq!(
        delivered,
        format!("served:2:0:1:0\n{session_text}\n{message_text}\n")
    );
    fixture::effect(
        case.peer,
        session,
        p::MessageId::from_trusted_state(message)?,
        PAYLOAD,
    )?;
    let (server, address) = case.server("rekey", "rekey", Some(&session_text))?;
    assert_eq!(
        case.run(
            "rekey",
            "rekey",
            &case.registry,
            &[session_text.clone(), address.to_string()]
        )?,
        "managed-rekey:1\n"
    );
    assert_eq!(receiver_process::finish(server, 0)?, "server-rekey-1\n");
    let next = identifier(&case.run(
        "next-rekey",
        "next",
        &case.registry,
        std::slice::from_ref(&session_text),
    )?)?;
    assert_ne!(next, message);
    let (server, address) = case.server("post-rekey", "message", Some(&session_text))?;
    assert_eq!(
        case.run(
            "post-rekey",
            "send",
            &case.registry,
            &[
                session_text.clone(),
                fixture::hex(&next),
                address.to_string()
            ]
        )?,
        "managed-consumed:3\n"
    );
    assert_eq!(
        receiver_process::finish(server, 0)?,
        format!("served:2:0:1:1\n{session_text}\n{}\n", fixture::hex(&next))
    );
    fixture::effect(
        case.peer,
        session,
        p::MessageId::from_trusted_state(next)?,
        PAYLOAD,
    )?;
    witness.join()?;
    assert!(witness
        .unprocessed
        .lock()
        .map_err(|_| "capture")?
        .is_empty());
    let captured = witness.captured.lock().map_err(|_| "witness transcript")?;
    assert!(!captured.is_empty());
    let mut transcript = Vec::new();
    for entry in captured.iter() {
        assert_eq!(entry.request.len(), 3674);
        assert_eq!(entry.reply.len(), 3659);
        assert!(entry.delivered);
        transcript.push(u8::from(entry.delivered));
        transcript.extend_from_slice(&entry.request);
        transcript.extend_from_slice(&entry.reply);
    }
    fixture::store(root, "managed-witness-transcript", &transcript)?;
    fixture::store(
        root,
        "managed-witness-exchanges",
        &u64::try_from(captured.len())?.to_be_bytes(),
    )?;
    fixture::store(root, "managed-session", &session)?;
    fixture::store(root, "managed-message", &message)?;
    fixture::store(root, "managed-next-message", &next)?;
    fixture::store(root, "managed-traffic-result", b"MANAGED_C_TRAFFIC same_session=true unknown_delivery=2 exact_retry=3 rekey=1 query_closed=202 send_closed=1202 new_registry_old_owner_closed=1202 closed_no_dispatch=true wrong_registry=211 bad_witness=218 release_qualified=false\n")?;
    Ok(())
}
