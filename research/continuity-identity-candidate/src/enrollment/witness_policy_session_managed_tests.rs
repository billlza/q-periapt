// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityIdentity, AccountAuthorityStore, ApplicationAccountId, InstallationAdmission,
    JournalAccountAuthority, MessageId,
};

fn registry(local: &Endpoint, peer: &Endpoint) -> (AccountAuthorityStore, JournalAccountAuthority) {
    let path = local
        .f
        ._witness_dir
        .path()
        .canonicalize()
        .expect("canonical owned fixture");
    let mut owner = AccountAuthorityStore::provision(
        &path.join("managed-registry"),
        JournalKey::provision(&path.join("managed-registry-key")).expect("independent key"),
        AccountAuthorityIdentity::generate().expect("independent registry identity"),
        local.f.c.policy.family(),
        local.f.pin.clone(),
    )
    .expect("registry");
    let application =
        |value| ApplicationAccountId::from_trusted_state([value; 32]).expect("application");
    let checkpoint = owner
        .associate(application(231), &local.f.original)
        .expect("original local root");
    owner
        .associate(application(232), &peer.f.original)
        .expect("independent peer root");
    let authority = JournalAccountAuthority::new(owner.access().expect("live owner"), checkpoint)
        .expect("descriptor");
    (owner, authority)
}

pub(super) fn reopen(
    local: &mut Endpoint,
    peer: &Endpoint,
    bundle: &BootstrapBundle,
    policy: Arc<VerifiedSessionPolicy>,
    session: [u8; 32],
    id: MessageId,
) {
    let (mut registry, authority) = registry(local, peer);
    local.owner = activate(&local.f, &policy);
    journal(&mut local.owner)
        .adopt_account_authority(authority.clone())
        .expect("explicit binding after witnessed G/T and rekey");
    let request = |local: &Endpoint| {
        bundle
            .request_historical_reopen(
                Arc::new(local.f.c.policy.historical().clone()),
                requirements(local, peer),
                BootstrapRole::Initiator,
                session,
                170,
            )
            .expect("original expired P0 identity")
    };
    let original = request(local);
    let continued = local
        .owner
        .parts()
        .expect("owner")
        .0
        .reopen_continued_peer(original, Arc::clone(&policy), 170)
        .expect("current P1 permission");
    let wire = journal(&mut local.owner)
        .resume_message(continued.context(), session, id, 170)
        .expect("original retained ciphertext");
    local.owner.close();
    let reopen = |authority: Option<JournalAccountAuthority>| {
        let mut enrollment = open(&local.f.c);
        let anchor = client(&local.f, &mut enrollment, 170);
        enrollment.close();
        let admission = match authority {
            Some(authority) => InstallationAdmission::managed(anchor, authority),
            None => Some(anchor).into(),
        };
        DeviceInstallation::reopen_continued_session(
            local.f.c.paths.installation.clone(),
            JournalKey::open(&local.f.c.paths.wrapping).expect("original key"),
            request(local),
            Arc::clone(&policy),
            170,
            admission,
        )
    };
    assert!(matches!(reopen(None), Err(DurableError::Conflict)));
    let reopened = reopen(Some(authority.clone())).expect("original managed continued session");
    assert_eq!(reopened.session_id(), session);
    let (mut service, context) = reopened.into_parts();
    assert_eq!(
        context.current_policy().expect("P1 owner").checkpoint(),
        policy.checkpoint()
    );
    let journal = service.stores().expect("existing journal").0;
    assert_eq!(
        journal
            .resume_message(&context, session, id, 170)
            .expect("exact old ciphertext"),
        wire
    );
    journal
        .next_message_id(&context, session, 170)
        .expect("continued traffic permission");
    registry.close();
    assert!(matches!(
        journal.resume_message(&context, session, id, 170),
        Err(DurableError::Closed)
    ));
    service.close();
    assert!(matches!(reopen(Some(authority)), Err(DurableError::Closed)));
    eprintln!("MANAGED_INSTALLED_CONTINUATION p0_expired=160 current=170 real_witnessed_g_t=true real_rekey=true exact_outbox=true closed_registry_refused=true");
}
