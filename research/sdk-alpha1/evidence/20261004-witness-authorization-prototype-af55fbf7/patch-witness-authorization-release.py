from pathlib import Path
import sys

p = Path(sys.argv[1]).resolve()
assert 'target/credential-renewal-20261004/' in str(p)

def replace(text, old, new, count=1):
    assert text.count(old) == count, (old[:80], text.count(old), count)
    return text.replace(old, new)

# Once independently committed to the exact mode, the legacy account-only
# observation must not authorize a caller that omitted the current statement.
f = p / 'src/anchor/store.rs'
s = f.read_text()
s = replace(s, 'if entry.authority == expected && live {',
    'if entry.renewal_authorization.is_none() && entry.authority == expected && live {')
f.write_text(s)

f = p / 'src/durable/rosters.rs'
s = f.read_text()
needle = 'pub(super) fn authorize_local_device('
s = replace(s, needle, '''// Experimental current exact credential-renewal authority, resolved from the
// authenticated image after current roster admission. None means original owner,
// never an expired/missing proof substitute. The witness refuses a legacy request
// if its independently retained current authorization is present.
pub(super) fn local_renewal_authorization(
    image: &Image,
    device: &VerifiedDevice,
    policy: &crate::VerifiedSessionPolicy,
) -> Result<Option<[u8; 32]>, DurableError> {
    check_local_device_scope(image, device, policy)?;
    if bootstrap::storage_owner(device) == image.owner {
        return Ok(None);
    }
    let saved = get(image, &image.local_account)?;
    let grant = saved.renewals.get(&device.device_id()).ok_or(DurableError::Conflict)?;
    Ok(Some(grant.statement_digest()))
}
''' + needle)
f.write_text(s)

f = p / 'src/durable/anchoring.rs'
s = f.read_text()
needle = '''                let reply = anchor.client.exchange(
                    anchor.subject,
                    AnchorOperation::admit_authority(device.authority_binding())?,
                )?;'''
s = replace(s, needle, '''                let operation = match rosters::local_renewal_authorization(&image, device, policy)? {
                    Some(statement) => AnchorOperation::admit_renewal(device.authority_binding(), statement)?,
                    None => AnchorOperation::admit_authority(device.authority_binding())?,
                };
                let reply = anchor.client.exchange(anchor.subject, operation)?;''')
f.write_text(s)

# Preserve the original counterexample result in the previous unmodified-source
# receipt. In this experimental mode the same old op4 is now explicitly denied;
# the paired new observations must still distinguish A and B at the same head.
f = p / 'src/enrollment/witness_renewal_tests.rs'
s = f.read_text()
s = replace(s, 'assert_eq!(admitted.outcome(), AnchorOutcome::AuthorityCurrent);',
    'assert_eq!(admitted.outcome(), AnchorOutcome::AuthorityDenied);', count=2)
f.write_text(s)
