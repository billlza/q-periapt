//! Private native issuer for real browser-generated enrollment requests.
use q_periapt_continuity_identity_candidate::{
    DeviceDescription, EnrollmentIntent, JournalKey, RootSigningKey, SigningKeyId, Validity,
    VerifiedEnrollmentRequest,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn intent(root: &RootSigningKey, directory: &Path) -> Result<EnrollmentIntent> {
    let bytes = fs::read(directory.join("description.bin"))?;
    if bytes.len() != 72 {
        return Err("description width".into());
    }
    let array = |start, end| bytes.get(start..end).ok_or("description field");
    let device = array(0, 16)?.try_into()?;
    let generation = u64::from_be_bytes(array(16, 24)?.try_into()?);
    let family = array(24, 56)?.try_into()?;
    let from = u64::from_be_bytes(array(56, 64)?.try_into()?);
    let until = u64::from_be_bytes(array(64, 72)?.try_into()?);
    Ok(EnrollmentIntent::new(
        root.public_key()?,
        DeviceDescription::new(device, generation, family, Validity::new(from, until)?)?,
    ))
}
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let mode = args.get(1).ok_or("mode")?;
    let directory = Path::new(args.get(2).ok_or("directory")?);
    match mode.as_str() {
        "prepare" => {
            if args.len() != 3 {
                return Err("prepare arguments".into());
            }
            let key = JournalKey::provision(&directory.join("private-wrap.key"))?;
            let id = SigningKeyId::generate()?;
            publish_private_bytes(&directory.join("root-id.bin"), id.as_bytes())?;
            let root = RootSigningKey::provision(&directory.join("private-root.key"), &key, id)?;
            let at = now()?;
            let mut description = vec![73; 16];
            description.extend_from_slice(&1u64.to_be_bytes());
            description.extend_from_slice(&[91; 32]);
            description.extend_from_slice(&at.saturating_sub(1).to_be_bytes());
            description.extend_from_slice(&at.checked_add(3600).ok_or("clock")?.to_be_bytes());
            publish_private_bytes(&directory.join("description.bin"), &description)?;
            publish_private_bytes(&directory.join("root.bin"), &root.public_key()?.encode())?;
            println!("native independent enrollment authority prepared");
        }
        "verify" => {
            if args.len() != 5 {
                return Err("verify arguments".into());
            }
            let key = JournalKey::open(&directory.join("private-wrap.key"))?;
            let id = SigningKeyId::from_trusted_state(
                fs::read(directory.join("root-id.bin"))?
                    .as_slice()
                    .try_into()?,
            )?;
            let root = RootSigningKey::open(&directory.join("private-root.key"), &key, id)?;
            if root.public_key()?.encode() != fs::read(directory.join("root.bin"))? {
                return Err("original authority changed".into());
            }
            let request = fs::read(args.get(3).ok_or("request")?)?;
            let verified =
                VerifiedEnrollmentRequest::verify(&request, &intent(&root, directory)?, now()?)?;
            let grant = root.issue_enrollment(&verified, now()?)?;
            publish_private_bytes(Path::new(args.get(4).ok_or("grant")?), &grant)?;
            println!(
                "request_sha256={} signing_identity={} public_key_sha256={} credential_sha256={}",
                hex(&Sha256::digest(&request)),
                hex(verified.identity().as_bytes()),
                hex(&Sha256::digest(verified.public_key().encode())),
                hex(&Sha256::digest(&grant))
            );
        }
        _ => return Err("unknown mode".into()),
    }
    Ok(())
}
