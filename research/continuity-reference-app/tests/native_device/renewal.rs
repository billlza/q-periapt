// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn original_native_renewal_request_exports_matched_history_without_signer_or_live_admission(
) -> Result<()> {
    let mut c = Case::open()?;
    let accepted = c.accept()?;
    let operation = [112; 32];
    let args = |prefix: &str, output: &str, endpoint: &str| {
        let mut args = c.args("renewal-request", &[]);
        args.extend([
            URL_SAFE_NO_PAD.encode(operation).into(),
            c.path.join(format!("{prefix}-pins.json")).into_os_string(),
            c.path
                .join(format!("{prefix}-materials.json"))
                .into_os_string(),
            endpoint.into(),
            c.path.join(output).into_os_string(),
        ]);
        args
    };
    invoke(&args("policy", "unprepared.json", "none"), false)?;
    assert!(!c.path.join("unprepared.json").exists());
    c.call(
        "prepare",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    )?;
    let mut activate = c.args(
        "activate",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    );
    activate.push("none".into());
    invoke(&activate, true)?;
    invoke(&args("policy", "wrong-endpoint.json", "127.0.0.1:1"), false)?;
    assert!(!c.path.join("wrong-endpoint.json").exists());
    // Local historical inspection needs original protected state, not a signer.
    // Preserve the file intact; this test does not delete or replace a key.
    fs::rename(
        c.path.join("device/device.key"),
        c.path.join("retained-original-device.key"),
    )?;
    let response: serde_json::Value =
        serde_json::from_slice(&invoke(&args("policy", "renewal1.json", "none"), true)?)?;
    assert_eq!(response["journal"], accepted["journal"]);
    assert_eq!(response["operation"], serde_json::json!(operation));
    invoke(&args("policy", "renewal2.json", "none"), true)?;
    let bytes = fs::read(c.path.join("renewal1.json"))?;
    assert_eq!(bytes, fs::read(c.path.join("renewal2.json"))?);
    let request: q_periapt_continuity_reference_app::native_device::RetainedCredentialRequest =
        serde_json::from_slice(&bytes)?;
    assert_eq!(request.schema, "qperiapt-retained-credential-request/1");
    assert_eq!(request.application, c.invitation.application);
    assert_eq!(request.enrollment, c.invitation.operation);
    assert_eq!(request.root_revision, c.invitation.root_revision);
    assert_eq!(request.original_certificate, c.issued.certificate);
    assert_eq!(request.previous_certificate, c.issued.certificate);
    assert_eq!(request.original_roster, c.issued.roster);
    assert_eq!(request.previous_roster, c.issued.roster);
    assert_eq!(request.previous_checkpoint, c.issued.checkpoint);
    assert_eq!(request.current_policy, request.original_policy);
    assert!(request.current_policy_authorization.is_none());
    assert_ne!(request.original_owner, [0; 32]);
    invoke(&args("policy", "renewal1.json", "none"), false)?;
    assert_eq!(bytes, fs::read(c.path.join("renewal1.json"))?);
    c.publisher.issue(
        [113; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: c.start,
            valid_until: c.start + 2400,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        clock()?,
    )?;
    c.policy_files([113; 32], "other")?;
    let mut wrong = c.args("renewal-request", &[]);
    wrong.extend([
        URL_SAFE_NO_PAD.encode(operation).into(),
        c.path.join("other-pins.json").into_os_string(),
        c.path.join("other-materials.json").into_os_string(),
        "none".into(),
        c.path.join("wrong-policy.json").into_os_string(),
    ]);
    invoke(&wrong, false)?;
    assert!(!c.path.join("wrong-policy.json").exists());
    // The ordinary operational path still requires the original signer.
    invoke(&activate, false)?;
    assert!(!c.path.join("device/device.key").exists());
    Ok(())
}
