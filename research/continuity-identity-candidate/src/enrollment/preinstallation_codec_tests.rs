// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn authenticated_extension_metadata_cannot_be_relabelled_truncated_or_detached() {
    for mutation in [
        "selected-flag",
        "extension-flag",
        "policy",
        "target",
        "truncated",
        "trailing",
        "downgrade",
        "duplicate-wrapper",
    ] {
        let (c, _, _, original) = setup();
        let p2 = policy_continuation::policy(&c, 2, 400, 210);
        let next = target(&c, &original, 46, None, 300, 210);
        let mut owner = open(&c);
        owner
            .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
            .expect("authentic extension");
        let image = owner.image().expect("image");
        let mut metadata = Vec::new();
        image
            .preparation
            .as_ref()
            .expect("marker")
            .encode(&mut metadata)
            .expect("encoded metadata");
        let bytes = row(&mut owner);
        let mut body = bytes.get(..bytes.len() - 32).expect("body").to_vec();
        let offset = body.len() - metadata.len();
        assert_eq!(body.get(offset..), Some(metadata.as_slice()));
        match mutation {
            "selected-flag" => *body.get_mut(offset).expect("selected flag") = 2,
            "extension-flag" => *body.get_mut(offset + 41).expect("extension flag") = 2,
            "policy" => *body.get_mut(offset + 9).expect("policy digest") ^= 1,
            "target" => *body.last_mut().expect("target digest") ^= 1,
            "truncated" => {
                body.pop();
            }
            "trailing" => body.push(0),
            "downgrade" => {
                body.drain(..8);
            }
            "duplicate-wrapper" => {
                body.splice(..0, b"QPENST19".iter().copied());
            }
            _ => unreachable!(),
        }
        let key = owner.key().expect("wrapping owner");
        let mut mac = auth(&key).expect("record authentication");
        mac.update(&body);
        body.extend_from_slice(&mac.finalize().into_bytes());
        write(
            &owner.active.as_ref().expect("configuration").database,
            &body,
        )
        .expect("explicit authenticated corruption fixture");
        owner.close();
        assert!(
            DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err(),
            "accepted {mutation}"
        );
        let raw = DeviceEnrollment::open_original_storage(c.paths.clone(), c.intent.clone())
            .expect("storage-only inspection");
        // The refusal must retain the malformed record for explicit recovery,
        // without rewriting it as a legacy or fresh installation.
        let db = &raw.active.as_ref().expect("original database").database;
        let tx = db.begin_read().expect("read transaction");
        let table = tx.open_table(TABLE).expect("enrollment table");
        assert_eq!(
            table
                .get("enrollment")
                .expect("row")
                .expect("retained row")
                .value(),
            body
        );
        for path in c.paths.installation.files() {
            assert!(!path.exists());
        }
    }
}
