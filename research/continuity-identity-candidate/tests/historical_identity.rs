// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public historical identity verification for retained issuer request materials.
use q_periapt_continuity_identity_candidate as p;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Case {
    root: p::RootSigningKey,
    signer: p::DeviceSigningKey,
    certificate: Vec<u8>,
    roster: p::IssuedRoster,
    pin: p::AccountPin,
}
fn case(c_from: u64, c_until: u64, r_from: u64, r_until: u64) -> Result<Case> {
    let root = p::RootSigningKey::generate()?;
    let signer = p::DeviceSigningKey::generate()?;
    let certificate = root.issue_device(
        p::DeviceDescription::new([7; 16], 1, [9; 32], p::Validity::new(c_from, c_until)?)?,
        signer.public_key()?,
    )?;
    let roster = root.issue_roster(
        1,
        p::Validity::new(r_from, r_until)?,
        &[root.roster_entry(&certificate)?],
    )?;
    let pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        [9; 32],
    )?;
    Ok(Case {
        root,
        signer,
        certificate,
        roster,
        pin,
    })
}
#[test]
fn historical_identity_round_trip_does_not_turn_expiry_into_current_permission() -> Result<()> {
    let c = case(100, 180, 120, 200)?;
    let historical = c
        .pin
        .verify_historical_device(&c.certificate, c.roster.as_bytes())?;
    let live = c
        .pin
        .verify_device(&c.certificate, c.roster.as_bytes(), 150)?;
    assert_eq!(historical.account_id(), live.account_id());
    assert_eq!(historical.device_id(), live.device_id());
    assert_eq!(historical.generation(), live.generation());
    assert_eq!(historical.credential_digest(), live.credential_digest());
    assert_eq!(historical.authority_binding(), live.authority_binding());
    assert_eq!(historical.roster().as_bytes(), c.roster.as_bytes());
    assert!(matches!(
        c.pin
            .verify_device(&c.certificate, c.roster.as_bytes(), 220),
        Err(p::Error::Validity)
    ));
    assert!(matches!(
        historical.roster().authorize_device(&historical, 220),
        Err(p::Error::Validity)
    ));
    Ok(())
}
#[test]
fn historical_identity_never_fabricates_an_overlap() -> Result<()> {
    for (cf, cu, rf, ru) in [
        (100, 180, 180, 250),
        (100, 180, 200, 250),
        (200, 250, 100, 180),
    ] {
        let c = case(cf, cu, rf, ru)?;
        assert!(matches!(
            c.pin
                .verify_historical_device(&c.certificate, c.roster.as_bytes()),
            Err(p::Error::Validity)
        ));
    }
    Ok(())
}
#[test]
fn historical_identity_rejects_signature_scope_and_exact_pin_substitution() -> Result<()> {
    let c = case(100, 180, 120, 200)?;
    let mut certificate = c.certificate.clone();
    *certificate.last_mut().ok_or("empty certificate")? ^= 1;
    assert!(matches!(
        c.pin
            .verify_historical_device(&certificate, c.roster.as_bytes()),
        Err(p::Error::Authentication)
    ));
    let mut roster = c.roster.as_bytes().to_vec();
    *roster.last_mut().ok_or("empty roster")? ^= 1;
    assert!(matches!(
        c.pin.verify_historical_device(&c.certificate, &roster),
        Err(p::Error::Authentication)
    ));
    let wrong_checkpoint =
        p::RosterCheckpoint::from_trusted_state(2, c.roster.checkpoint().digest())?;
    let wrong = p::AccountPin::new(
        c.root.account_id()?,
        c.root.public_key()?,
        wrong_checkpoint,
        [9; 32],
    )?;
    assert!(matches!(
        wrong.verify_historical_device(&c.certificate, c.roster.as_bytes()),
        Err(p::Error::Checkpoint)
    ));
    let wrong = p::AccountPin::new(
        c.root.account_id()?,
        c.root.public_key()?,
        c.roster.checkpoint(),
        [8; 32],
    )?;
    assert!(matches!(
        wrong.verify_historical_device(&c.certificate, c.roster.as_bytes()),
        Err(p::Error::Scope)
    ));
    let another = p::RootSigningKey::generate()?;
    let forged = another.issue_device(
        p::DeviceDescription::new([7; 16], 1, [9; 32], p::Validity::new(100, 180)?)?,
        c.signer.public_key()?,
    )?;
    assert!(matches!(
        c.pin.verify_historical_device(&forged, c.roster.as_bytes()),
        Err(p::Error::Authentication)
    ));
    let mut trailing = c.certificate.clone();
    trailing.push(0);
    assert!(c
        .pin
        .verify_historical_device(&trailing, c.roster.as_bytes())
        .is_err());
    Ok(())
}
#[test]
fn historical_identity_does_not_override_revocation_or_generation() -> Result<()> {
    let c = case(100, 180, 120, 200)?;
    let replacement = c.root.issue_device(
        p::DeviceDescription::new([7; 16], 2, [9; 32], p::Validity::new(100, 180)?)?,
        c.signer.public_key()?,
    )?;
    for entries in [Vec::new(), vec![c.root.roster_entry(&replacement)?]] {
        let roster = c
            .root
            .issue_roster(2, p::Validity::new(120, 200)?, &entries)?;
        let pin = p::AccountPin::new(
            c.root.account_id()?,
            c.root.public_key()?,
            roster.checkpoint(),
            [9; 32],
        )?;
        assert!(matches!(
            pin.verify_historical_device(&c.certificate, roster.as_bytes()),
            Err(p::Error::Scope)
        ));
    }
    Ok(())
}
