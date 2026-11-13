// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{AnchorSigningKey, DeviceSigningKey, PolicySigningKey, RootSigningKey};
use q_periapt_host_store::filesystem::publish_private_bytes;
use q_periapt_sdk::{Limits, Runtime};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

const DOCUMENT: &[u8] = b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn directory() -> Result<PathBuf> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.keep().canonicalize()?;
    eprintln!(
        "SDK policy signer private fixture retained: {}",
        path.display()
    );
    Ok(path)
}

#[test]
fn exact_sdk_signature_reopens_and_closed_capability_cannot_sign() -> Result<()> {
    let path = directory()?;
    let wrapping = JournalKey::provision(&path.join("wrapping"))?;
    let identity = SigningKeyId::generate()?;
    let file = path.join("sdk-signer");
    let mut owner = SdkPolicySigningKey::provision(&file, &wrapping, identity)?;
    let root = owner.public_key()?;
    let signature = owner.sign_policy(DOCUMENT)?;
    let original = fs::read(&file)?;
    let runtime =
        Runtime::from_signed_policy(DOCUMENT, &signature, &root, None, Limits::default())?;
    assert!(runtime.is_enabled()?);
    assert_eq!(runtime.trusted_state().version(), 1);
    assert!(MlDsa65
        .verify_ctx(&root, DOCUMENT, &[], &signature)
        .is_err());
    assert!(MlDsa65
        .verify_ctx(
            &root,
            &policy_signature_message(DOCUMENT),
            crate::contract::SIGNATURE_CONTEXT,
            &signature
        )
        .is_err());
    owner.close();
    owner.close();
    assert!(matches!(owner.public_key(), Err(Error::Closed)));
    assert!(matches!(owner.sign_policy(DOCUMENT), Err(Error::Closed)));
    assert_eq!(fs::read(&file)?, original);
    let restored = SdkPolicySigningKey::open(&file, &wrapping, identity)?;
    assert_eq!(restored.public_key()?, root);
    let successor = std::str::from_utf8(DOCUMENT)?.replace("policy_version=1", "policy_version=2");
    let next = restored.sign_policy(successor.as_bytes())?;
    let runtime = Runtime::from_signed_policy(
        successor.as_bytes(),
        &next,
        &root,
        Some(&runtime.trusted_state()),
        Limits::default(),
    )?;
    assert_eq!(runtime.trusted_state().version(), 2);
    assert_eq!(fs::read(&file)?, original);
    Ok(())
}

#[test]
fn sdk_file_cannot_be_used_by_other_roles_or_replaced_on_reopen() -> Result<()> {
    let path = directory()?;
    let wrapping = JournalKey::provision(&path.join("wrapping"))?;
    let other = JournalKey::provision(&path.join("other-wrapping"))?;
    let identity = SigningKeyId::generate()?;
    let file = path.join("sdk-signer");
    let owner = SdkPolicySigningKey::provision(&file, &wrapping, identity)?;
    let root = owner.public_key()?;
    let original = fs::read(&file)?;
    assert!(!original.windows(root.len()).any(|part| part == root));
    assert!(RootSigningKey::open(&file, &wrapping, identity).is_err());
    assert!(DeviceSigningKey::open(&file, &wrapping, identity).is_err());
    assert!(PolicySigningKey::open(&file, &wrapping, identity).is_err());
    assert!(AnchorSigningKey::open(&file, &wrapping, identity).is_err());
    assert!(SdkPolicySigningKey::open(&file, &other, identity).is_err());
    assert!(SdkPolicySigningKey::open(&file, &wrapping, SigningKeyId::generate()?).is_err());
    assert!(SdkPolicySigningKey::provision(&file, &wrapping, identity).is_err());
    assert_eq!(fs::read(&file)?, original);
    let account_file = path.join("account-signer");
    let account = RootSigningKey::provision(&account_file, &wrapping, identity)?;
    assert!(SdkPolicySigningKey::open(&account_file, &wrapping, identity).is_err());
    drop(account);
    drop(owner);
    fs::rename(&file, path.join("original-sdk-signer.retained"))?;
    assert!(SdkPolicySigningKey::open(&file, &wrapping, identity).is_err());
    assert!(!file.exists());
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("empty encrypted signer")? ^= 1;
    publish_private_bytes(&file, &corrupt)?;
    assert!(SdkPolicySigningKey::open(&file, &wrapping, identity).is_err());
    assert_eq!(fs::read(&file)?, corrupt);
    assert_eq!(
        fs::read(path.join("original-sdk-signer.retained"))?,
        original
    );
    Ok(())
}

#[test]
fn invalid_or_too_strong_sdk_documents_never_obtain_a_signature() -> Result<()> {
    let path = directory()?;
    let wrapping = JournalKey::provision(&path.join("wrapping"))?;
    let identity = SigningKeyId::generate()?;
    let file = path.join("sdk-signer");
    let owner = SdkPolicySigningKey::provision(&file, &wrapping, identity)?;
    let original = fs::read(&file)?;
    for document in [
        Vec::new(),
        vec![0xff],
        vec![b' '; MAX_SIGNED_POLICY_BYTES + 1],
        b"schema_version=1".to_vec(),
    ] {
        assert!(owner.sign_policy(&document).is_err());
    }
    let stronger = std::str::from_utf8(DOCUMENT)?
        .replace("min_nist_level=3", "min_nist_level=5")
        .replace("ML-KEM-768", "ML-KEM-1024")
        .replace("ML-DSA-65", "ML-DSA-87");
    assert!(matches!(
        owner.sign_policy(stronger.as_bytes()),
        Err(Error::Scope)
    ));
    assert_eq!(fs::read(&file)?, original);
    assert!(owner.sign_policy(DOCUMENT).is_ok());
    Ok(())
}
