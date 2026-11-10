// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::crash::{kill_at, Work};
use super::*;

#[test]
fn authority_schema_and_initialization_kills_recover_original_registry_and_keys() -> Result {
    for boundary in [
        "authority-upgrade-before-commit",
        "authority-upgrade-after-commit",
        "authority-association-retained",
        "authority-wrapping-published",
        "authority-registry-prepared",
        "authority-registry-committed",
        "authority-ready-committed",
    ] {
        let mut c = Case::new()?;
        let upgrading = boundary.starts_with("authority-upgrade");
        if !upgrading {
            c.host.store.enable_account_authorities()?;
        }
        let account = serde_json::to_vec(&c.host.store.account("alice")?.ok_or("account")?)?;
        drop(c.host);
        let marker = kill_at(
            &c.path,
            boundary,
            if upgrading {
                Work::AuthorityUpgrade
            } else {
                Work::AssociateAuthority(Box::new(c.request.clone()))
            },
        )?;
        let original_keys = authority_files(&c.path)?
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "wrap"))
            .map(|p| fs::read(&p).map(|bytes| (p, bytes)))
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut host = reopen(&c.path)?;
        assert_eq!(
            serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
            account
        );
        let (token, _) = login(&mut host, &mut c.auth, "alice")?;
        assert_eq!(host.enrollment_root(&token)?, c.root);
        if !upgrading && boundary != "authority-ready-committed" {
            assert!(matches!(
                host.invite_enrollment(&token, crate::enrollment::random()?),
                Err(Error::Conflict(_))
            ));
        }
        if boundary == "authority-upgrade-before-commit" {
            assert!(matches!(
                host.associate_account_authority(&token, &c.request),
                Err(Error::Conflict(_))
            ));
        } else if upgrading {
            host.associate_account_authority(&token, &c.request)?;
        }
        host.store.enable_account_authorities()?;
        let original = host.associate_account_authority(&token, &c.request)?;
        assert_eq!(original.initialization, Initialization::Initialized);
        assert!(host.associate_account_authority(&token, &c.request)? == original);
        assert!(host.account_authority(&token)? == original);
        assert_eq!(host.enrollment_root(&token)?, c.root);
        let files = authority_files(&c.path)?;
        assert_eq!(files.len(), 2);
        if !upgrading {
            let stem = format!("authority-{}.", URL_SAFE_NO_PAD.encode(marker));
            assert!(files.iter().all(|p| p
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(&stem))));
        }
        for (path, bytes) in original_keys {
            assert!(
                fs::read(path)? == bytes,
                "original authority wrapping file changed"
            );
        }
    }
    Ok(())
}
