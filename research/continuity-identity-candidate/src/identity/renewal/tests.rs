// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::DeviceSigningKey;

struct Case {
    root: RootSigningKey,
    key: DeviceSigningKey,
    origin: Vec<u8>,
    previous: Vec<u8>,
    successor: Vec<u8>,
    old_roster: IssuedRoster,
    new_roster: IssuedRoster,
    authorization: CredentialRenewalAuthorization,
    pin: AccountPin,
}
impl Case {
    fn new() -> Self {
        let root = RootSigningKey::generate().expect("root");
        let key = DeviceSigningKey::generate().expect("device");
        let issue = |until| {
            root.issue_device(
                DeviceDescription::new(
                    [7; 16],
                    1,
                    [8; 32],
                    Validity::new(100, until).expect("time"),
                )
                .expect("description"),
                key.public_key().expect("public"),
            )
            .expect("certificate")
        };
        let origin = issue(160);
        let previous = issue(200);
        let successor = issue(300);
        let old_roster = root
            .issue_roster(
                2,
                Validity::new(170, 210).expect("time"),
                &[root.roster_entry(&previous).expect("old entry")],
            )
            .expect("old roster");
        let new_roster = root
            .issue_roster(
                3,
                Validity::new(210, 290).expect("time"),
                &[root.roster_entry(&successor).expect("new entry")],
            )
            .expect("new roster");
        let pin = AccountPin::new(
            root.account_id().expect("account"),
            root.public_key().expect("root public"),
            new_roster.checkpoint(),
            [8; 32],
        )
        .expect("current pin");
        let authorization = CredentialRenewalAuthorization {
            operation: CredentialRenewalId::from_trusted_state([9; 32]).expect("operation"),
            previous: old_roster.checkpoint(),
            policy_digest: [10; 32],
        };
        Self {
            root,
            key,
            origin,
            previous,
            successor,
            old_roster,
            new_roster,
            authorization,
            pin,
        }
    }
    fn materials(&self) -> CredentialRenewalMaterials<'_> {
        CredentialRenewalMaterials {
            original_credential: &self.origin,
            previous_credential: &self.previous,
            successor_credential: &self.successor,
            previous_roster: self.old_roster.as_bytes(),
            successor_roster: self.new_roster.as_bytes(),
        }
    }
    fn issued(&self) -> IssuedCredentialRenewal {
        self.root
            .issue_credential_renewal(self.materials(), &self.authorization, &self.pin, 220)
            .expect("grant")
    }
    fn verify(&self, bytes: &[u8]) -> Result<VerifiedCredentialRenewal, Error> {
        VerifiedCredentialRenewal::verify(bytes, &self.pin, self.authorization.policy_digest, 220)
    }
}

#[test]
fn exact_root_policy_key_and_historical_predecessor_bind_the_statement() {
    let c = Case::new();
    let issued = c.issued();
    let relation = c.verify(issued.as_bytes()).expect("verified relation");
    assert_eq!(relation.operation(), c.authorization.operation);
    assert_eq!(relation.policy_digest(), c.authorization.policy_digest);
    assert_eq!(relation.as_bytes(), issued.as_bytes());
    assert_eq!(
        relation.previous_device().roster().checkpoint(),
        c.old_roster.checkpoint()
    );
    assert_eq!(
        relation.successor_device().roster().checkpoint(),
        c.new_roster.checkpoint()
    );
    assert!(relation
        .previous_device()
        .description
        .validity
        .check(220)
        .is_err());
    relation
        .successor_device()
        .description
        .validity
        .check(220)
        .expect("current target");
    let origin_roster = c
        .root
        .issue_roster(
            1,
            Validity::new(100, 170).expect("time"),
            &[c.root.roster_entry(&c.origin).expect("original entry")],
        )
        .expect("origin roster");
    let original = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        origin_roster.checkpoint(),
        [8; 32],
    )
    .expect("old pin")
    .verify_device(&c.origin, origin_roster.as_bytes(), 150)
    .expect("original identity");
    assert_eq!(
        relation.original_credential_digest(),
        original.credential_digest()
    );
    assert_eq!(
        relation.original_storage_owner(),
        crate::bootstrap::storage_owner(&original)
    );
    assert_ne!(
        relation.original_storage_owner(),
        crate::bootstrap::storage_owner(relation.successor_device())
    );
    assert_eq!(
        relation.statement_digest(),
        c.verify(c.issued().as_bytes())
            .expect("same grant")
            .statement_digest()
    );
    assert!(matches!(
        VerifiedCredentialRenewal::verify(issued.as_bytes(), &c.pin, [11; 32], 220),
        Err(Error::Scope)
    ));
    assert!(matches!(
        VerifiedCredentialRenewal::verify(issued.as_bytes(), &c.pin, [10; 32], 300),
        Err(Error::Validity)
    ));
}

#[test]
fn wrong_purpose_each_signature_and_container_corruption_are_refused() {
    let c = Case::new();
    let issued = c.issued();
    let mut d = Decoder::new(issued.as_bytes());
    d.take(8).expect("tag");
    let (body, signature) = open_envelope(field(&mut d).expect("statement")).expect("envelope");
    let wrong_purpose = envelope(
        body,
        &c.root
            .sign(Purpose::Credential, body)
            .expect("different purpose"),
    )
    .expect("envelope");
    assert!(matches!(
        c.verify(&container(&wrong_purpose, &c.materials()).expect("container")),
        Err(Error::Authentication)
    ));
    for index in [0, crate::crypto::SIGNATURE_BYTES - 1] {
        let mut changed = signature.to_vec();
        *changed.get_mut(index).expect("signature component") ^= 1;
        let signed = envelope(body, &changed).expect("sized signature");
        assert!(c
            .verify(&container(&signed, &c.materials()).expect("container"))
            .is_err());
    }
    for index in [0, 8, 9, 10, issued.as_bytes().len() - 1] {
        let mut changed = issued.as_bytes().to_vec();
        *changed.get_mut(index).expect("wire index") ^= 1;
        assert!(
            c.verify(&changed).is_err(),
            "accepted corruption at {index}"
        );
    }
    let mut extra = issued.as_bytes().to_vec();
    extra.push(0);
    assert!(matches!(c.verify(&extra), Err(Error::Encoding)));
    assert!(c
        .verify(
            issued
                .as_bytes()
                .get(..issued.as_bytes().len() - 1)
                .expect("truncated wire")
        )
        .is_err());
    assert!(matches!(
        c.verify(&vec![0; MAX_CREDENTIAL_RENEWAL_BYTES + 1]),
        Err(Error::Capacity)
    ));
}

#[test]
fn separately_signed_but_inconsistent_statement_fields_are_refused() {
    let c = Case::new();
    let (base, _, _) =
        check_materials(&c.materials(), &c.authorization, &c.pin, 220).expect("materials");
    let variants = [
        Statement {
            account: [42; 32],
            ..base.clone()
        },
        Statement {
            device: [42; 16],
            ..base.clone()
        },
        Statement {
            generation: 2,
            ..base.clone()
        },
        Statement {
            family: [42; 32],
            ..base.clone()
        },
        Statement {
            key: [42; 32],
            ..base.clone()
        },
        Statement {
            original: [42; 32],
            ..base.clone()
        },
        Statement {
            previous: [42; 32],
            ..base.clone()
        },
        Statement {
            successor: [42; 32],
            ..base.clone()
        },
    ];
    for changed in variants {
        let body = changed.encode();
        let signed = envelope(
            &body,
            &c.root
                .sign(Purpose::CredentialRenewal, &body)
                .expect("signed assertion"),
        )
        .expect("envelope");
        assert!(matches!(
            c.verify(&container(&signed, &c.materials()).expect("container")),
            Err(Error::Scope)
        ));
    }
}

#[test]
fn device_generation_key_account_and_non_extension_cannot_be_renewed() {
    let c = Case::new();
    let other = DeviceSigningKey::generate().expect("other key");
    let other_bytes = other.public_key().expect("other public").encode();
    let boundary = q_periapt_backends::ML_DSA_65_VK_LEN;
    let mut same_pq = c.key.public_key().expect("original public").encode();
    same_pq
        .get_mut(boundary..)
        .expect("classic component")
        .copy_from_slice(other_bytes.get(boundary..).expect("other classic"));
    let mut same_classic = c.key.public_key().expect("original public").encode();
    same_classic
        .get_mut(..boundary)
        .expect("PQ component")
        .copy_from_slice(other_bytes.get(..boundary).expect("other PQ"));
    for (id, generation, key, from, until) in [
        ([6; 16], 1, c.key.public_key().expect("key"), 100, 300),
        ([7; 16], 2, c.key.public_key().expect("key"), 100, 300),
        (
            [7; 16],
            1,
            other.public_key().expect("other public"),
            100,
            300,
        ),
        (
            [7; 16],
            1,
            PublicKey::decode(&same_pq).expect("same PQ only"),
            100,
            300,
        ),
        (
            [7; 16],
            1,
            PublicKey::decode(&same_classic).expect("same classic only"),
            100,
            300,
        ),
        ([7; 16], 1, c.key.public_key().expect("key"), 101, 300),
        ([7; 16], 1, c.key.public_key().expect("key"), 100, 200),
    ] {
        let cert = c
            .root
            .issue_device(
                DeviceDescription::new(
                    id,
                    generation,
                    [8; 32],
                    Validity::new(from, until).expect("interval"),
                )
                .expect("description"),
                key,
            )
            .expect("certificate");
        let roster = c
            .root
            .issue_roster(
                3,
                Validity::new(150, 290).expect("time"),
                &[c.root.roster_entry(&cert).expect("entry")],
            )
            .expect("roster");
        let pin = AccountPin::new(
            c.root.account_id().expect("account"),
            c.root.public_key().expect("root"),
            roster.checkpoint(),
            [8; 32],
        )
        .expect("pin");
        let materials = CredentialRenewalMaterials {
            successor_credential: &cert,
            successor_roster: roster.as_bytes(),
            ..c.materials()
        };
        assert!(c
            .root
            .issue_credential_renewal(materials, &c.authorization, &pin, 180)
            .is_err());
    }
    let other_root = RootSigningKey::generate().expect("other root");
    assert!(matches!(
        other_root.issue_credential_renewal(c.materials(), &c.authorization, &c.pin, 220),
        Err(Error::Scope)
    ));
    let issued = c.issued();
    let wrong = AccountPin::new(
        other_root.account_id().expect("account"),
        other_root.public_key().expect("root"),
        c.new_roster.checkpoint(),
        [8; 32],
    )
    .expect("other pin");
    assert!(matches!(
        VerifiedCredentialRenewal::verify(issued.as_bytes(), &wrong, [10; 32], 220),
        Err(Error::Authentication)
    ));
}

#[test]
fn first_renewal_binds_original_and_predecessor_without_granting_new_storage() {
    let c = Case::new();
    let previous = c
        .root
        .issue_roster(
            1,
            Validity::new(100, 170).expect("historical time"),
            &[c.root.roster_entry(&c.origin).expect("original entry")],
        )
        .expect("original roster");
    let authorization = CredentialRenewalAuthorization {
        operation: c.authorization.operation,
        previous: previous.checkpoint(),
        policy_digest: [10; 32],
    };
    let materials = CredentialRenewalMaterials {
        previous_credential: &c.origin,
        previous_roster: previous.as_bytes(),
        ..c.materials()
    };
    let issued = c
        .root
        .issue_credential_renewal(materials, &authorization, &c.pin, 220)
        .expect("first explicit renewal grant");
    let relation = c.verify(issued.as_bytes()).expect("first relation");
    assert_eq!(
        relation.original_credential_digest(),
        relation.previous_device().credential_digest()
    );
    assert_ne!(
        relation.original_credential_digest(),
        relation.successor_device().credential_digest()
    );
    assert_eq!(
        relation.original_storage_owner(),
        crate::bootstrap::storage_owner(relation.previous_device())
    );
    let (mut statement, _, _) =
        check_materials(&c.materials(), &c.authorization, &c.pin, 220).expect("statement");
    statement.policy = [10; 32];
    let mut body = statement.encode();
    *body.last_mut().expect("permission") = 2;
    let signed = envelope(
        &body,
        &c.root
            .sign(Purpose::CredentialRenewal, &body)
            .expect("signed unknown permission"),
    )
    .expect("envelope");
    assert!(matches!(
        c.verify(&container(&signed, &c.materials()).expect("container")),
        Err(Error::Encoding)
    ));
}

#[test]
fn missing_membership_forked_checkpoints_and_nonoverlapping_history_are_refused() {
    let c = Case::new();
    let empty = c
        .root
        .issue_roster(3, Validity::new(210, 290).expect("time"), &[])
        .expect("revocation");
    let empty_pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        empty.checkpoint(),
        [8; 32],
    )
    .expect("pin");
    let materials = CredentialRenewalMaterials {
        successor_roster: empty.as_bytes(),
        ..c.materials()
    };
    assert!(matches!(
        c.root
            .issue_credential_renewal(materials, &c.authorization, &empty_pin, 220),
        Err(Error::Scope)
    ));
    let past = c
        .root
        .issue_roster(
            2,
            Validity::new(201, 250).expect("no overlap"),
            &[c.root.roster_entry(&c.previous).expect("entry")],
        )
        .expect("past roster");
    let authorization = CredentialRenewalAuthorization {
        operation: c.authorization.operation,
        previous: past.checkpoint(),
        policy_digest: [10; 32],
    };
    let materials = CredentialRenewalMaterials {
        previous_roster: past.as_bytes(),
        ..c.materials()
    };
    assert!(matches!(
        c.root
            .issue_credential_renewal(materials, &authorization, &c.pin, 220),
        Err(Error::Validity)
    ));
    let authorization = CredentialRenewalAuthorization {
        operation: c.authorization.operation,
        previous: c.new_roster.checkpoint(),
        policy_digest: [10; 32],
    };
    assert!(matches!(
        c.root
            .issue_credential_renewal(c.materials(), &authorization, &c.pin, 220),
        Err(Error::Checkpoint)
    ));
    let fork = RosterCheckpoint::from_trusted_state(3, [42; 32]).expect("fork");
    let fork_pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        fork,
        [8; 32],
    )
    .expect("fork pin");
    assert!(matches!(
        c.root
            .issue_credential_renewal(c.materials(), &c.authorization, &fork_pin, 220),
        Err(Error::Checkpoint)
    ));
}

#[test]
fn a_future_predecessor_membership_is_not_historical_authority() {
    let c = Case::new();
    let target = c
        .root
        .issue_device(
            DeviceDescription::new(
                [7; 16],
                1,
                [8; 32],
                Validity::new(100, 400).expect("target time"),
            )
            .expect("description"),
            c.key.public_key().expect("same complete key"),
        )
        .expect("target credential");
    let future = c
        .root
        .issue_roster(
            2,
            Validity::new(230, 260).expect("future membership"),
            &[c.root
                .roster_entry(&c.successor)
                .expect("predecessor entry")],
        )
        .expect("future roster");
    let current = c
        .root
        .issue_roster(
            3,
            Validity::new(210, 390).expect("current membership"),
            &[c.root.roster_entry(&target).expect("target entry")],
        )
        .expect("current roster");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        current.checkpoint(),
        [8; 32],
    )
    .expect("independent pin");
    let authorization = CredentialRenewalAuthorization {
        operation: c.authorization.operation,
        previous: future.checkpoint(),
        policy_digest: [10; 32],
    };
    let materials = || CredentialRenewalMaterials {
        original_credential: &c.origin,
        previous_credential: &c.successor,
        successor_credential: &target,
        previous_roster: future.as_bytes(),
        successor_roster: current.as_bytes(),
    };
    assert!(matches!(
        c.root
            .issue_credential_renewal(materials(), &authorization, &pin, 220),
        Err(Error::Validity)
    ));
    let later = c
        .root
        .issue_credential_renewal(materials(), &authorization, &pin, 240)
        .expect("grant after predecessor activation");
    assert!(matches!(
        VerifiedCredentialRenewal::verify(later.as_bytes(), &pin, [10; 32], 220),
        Err(Error::Validity)
    ));
    VerifiedCredentialRenewal::verify(later.as_bytes(), &pin, [10; 32], 240)
        .expect("current verified relation");
}

#[test]
fn historical_grant_authenticates_expired_materials_without_current_target_authority() {
    let c = Case::new();
    let issued = c.issued();
    assert!(matches!(
        VerifiedCredentialRenewal::verify(
            issued.as_bytes(),
            &c.pin,
            c.authorization.policy_digest,
            300
        ),
        Err(Error::Validity)
    ));
    let historical = HistoricalCredentialRenewal::verify(
        issued.as_bytes(),
        &c.pin,
        c.authorization.policy_digest,
    )
    .expect("original historical signatures and exact pin");
    let current = c.verify(issued.as_bytes()).expect("live reference");
    assert_eq!(historical.as_bytes(), issued.as_bytes());
    assert_eq!(historical.operation(), current.operation());
    assert_eq!(historical.statement_digest(), current.statement_digest());
    assert_eq!(
        historical.original_storage_owner(),
        current.original_storage_owner()
    );
    assert_eq!(historical.successor_checkpoint(), c.new_roster.checkpoint());
    assert!(historical
        .successor_device()
        .description
        .validity
        .check(300)
        .is_err());
    assert!(historical
        .successor_device()
        .roster_validity
        .check(300)
        .is_err());
}

#[test]
fn historical_grant_still_requires_original_independent_pin_and_all_signed_fields() {
    let c = Case::new();
    let issued = c.issued();
    let bytes = issued.as_bytes();
    let mut decoder = Decoder::new(bytes);
    assert_eq!(decoder.array::<8>().expect("tag"), *CONTAINER);
    let mut offset = 10;
    for _ in 0..6 {
        let value = field(&mut decoder).expect("field");
        let mut changed = bytes.to_vec();
        *changed
            .get_mut(offset + value.len() - 1)
            .expect("signed field byte") ^= 1;
        offset += value.len() + 2;
        assert!(HistoricalCredentialRenewal::verify(
            &changed,
            &c.pin,
            c.authorization.policy_digest
        )
        .is_err());
    }
    for changed in [
        bytes
            .get(..bytes.len() - 1)
            .expect("truncated container")
            .to_vec(),
        [bytes, b"x"].concat(),
    ] {
        assert!(HistoricalCredentialRenewal::verify(
            &changed,
            &c.pin,
            c.authorization.policy_digest
        )
        .is_err());
    }
    assert!(HistoricalCredentialRenewal::verify(bytes, &c.pin, [11; 32]).is_err());
    let stale = AccountPin::new(
        c.pin.account,
        c.pin.root.clone(),
        c.old_roster.checkpoint(),
        c.pin.family,
    )
    .expect("independent stale pin");
    assert!(
        HistoricalCredentialRenewal::verify(bytes, &stale, c.authorization.policy_digest).is_err()
    );
    let wrong_root = RootSigningKey::generate().expect("different root");
    let wrong = AccountPin::new(
        wrong_root.account_id().expect("account"),
        wrong_root.public_key().expect("root"),
        c.new_roster.checkpoint(),
        c.pin.family,
    )
    .expect("different independent pin");
    assert!(
        HistoricalCredentialRenewal::verify(bytes, &wrong, c.authorization.policy_digest).is_err()
    );
}
