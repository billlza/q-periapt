use super::*;
use crate::enrollment::policy::renewal;
use std::mem::MaybeUninit;

/// Exercise the C policy selector after independent policy adoption, before
/// activation reconciles the same original journal. The caller owns the registry lease.
pub(super) fn stage(
    handle: u64,
    request: &renewal::PolicyRequest,
    previous: &enrollment::Pin,
    root: &p::RootSigningKey,
) -> TestResult<()> {
    let certificate = request
        .original_credential
        .bytes
        .get(..usize::try_from(request.original_credential.length)?)
        .ok_or("original credential record")?;
    let now = fixture::now()?;
    let issued = root.issue_roster(
        previous
            .checkpoint
            .version
            .checked_add(1)
            .ok_or("roster version")?,
        p::Validity::new(now, now.checked_add(600).ok_or("roster validity")?)?,
        &[root.roster_entry(certificate)?],
    )?;
    let public = root.public_key()?.encode();
    let pin = enrollment::Pin {
        account: root.account_id()?,
        root: public.as_ptr(),
        root_length: public.len(),
        family: previous.family,
        checkpoint: enrollment::Checkpoint {
            version: issued.checkpoint().version(),
            digest: issued.checkpoint().digest(),
        },
    };
    let mut status = MaybeUninit::<enrollment::Status>::uninit();
    let mut error = diagnostic();
    // SAFETY: every public input remains live and immutable; status and error are
    // separate aligned outputs. Only successful calls initialize status for reads.
    unsafe {
        assert_eq!(
            enrollment::qpc_enrollment_v1_refresh_roster_with_policy(
                handle,
                2,
                &previous.checkpoint,
                issued.as_bytes().as_ptr(),
                issued.as_bytes().len(),
                &pin,
                status.as_mut_ptr(),
                &mut error,
            ),
            1,
            "unknown policy choice must be rejected before owner admission"
        );
        for _ in 0..2 {
            checked(
                enrollment::qpc_enrollment_v1_refresh_roster_with_policy(
                    handle,
                    1,
                    &previous.checkpoint,
                    issued.as_bytes().as_ptr(),
                    issued.as_bytes().len(),
                    &pin,
                    status.as_mut_ptr(),
                    &mut error,
                ),
                &error,
            )?;
            let observed = status.assume_init_ref();
            assert_eq!(observed.phase, 6, "staging is not an activation receipt");
            assert_eq!(observed.journal, request.scope.journal);
            assert_eq!(observed.previous.version, previous.checkpoint.version);
            assert_eq!(observed.previous.digest, previous.checkpoint.digest);
            assert_eq!(observed.next.version, pin.checkpoint.version);
            assert_eq!(observed.next.digest, pin.checkpoint.digest);
        }
    }
    Ok(())
}
