from pathlib import Path
import sys

# Applies only to a fresh isolated candidate copy. It is not a migration or a
# production policy-renewal implementation. Existing credential transactions
# provide real authorized commits for testing the persistent binding mechanism.
p = Path(sys.argv[1]).resolve()
assert 'target/credential-renewal-20261004/' in str(p)

def replace(text, old, new, count=1):
    assert text.count(old) == count, (old[:80], text.count(old), count)
    return text.replace(old, new)

f = p / 'src/anchor.rs'
s = f.read_text()
s = replace(s, '    AdmitAuthority([u8; 32]),', '    AdmitAuthority([u8; 32]),\n    AdmitRenewal([u8; 32], [u8; 32]),')
needle = '    /// Apply only the independently prepared exact joint head/credential target.'
s = replace(s, needle, '''    /// Experimental single-observation check of account and renewal authority.
    /// No local owner release or policy-renewal semantics are implied.
    pub fn admit_renewal(authority: [u8; 32], statement: [u8; 32]) -> Result<Self, Error> {
        nonzero(&authority)?;
        nonzero(&statement)?;
        Ok(Self(Command::AdmitRenewal(authority, statement)))
    }
''' + needle)
s = replace(s, '            Command::Advance(before, after) | Command::Fence(before, after) => {', '''            Command::AdmitRenewal(authority, statement) => {
                out.push(9);
                out.extend_from_slice(&authority);
                out.extend_from_slice(&statement);
                out.extend_from_slice(&[0; 32]);
            }
            Command::Advance(before, after) | Command::Fence(before, after) => {''')
s = replace(s, '        if (4..=8).contains(&kind) {', '''        if kind == 9 {
            let authority = d.array()?;
            let statement = d.array()?;
            if d.take(32)?.iter().any(|byte| *byte != 0) {
                return Err(Error::Encoding);
            }
            return Self::admit_renewal(authority, statement);
        }
        if (4..=8).contains(&kind) {''')
s = replace(s, '            | Command::AdmitAuthority(_)\n', '            | Command::AdmitAuthority(_)\n            | Command::AdmitRenewal(..)\n')
s = replace(s, '                Command::AdmitAuthority(_),\n                AnchorOutcome::AuthorityCurrent', '                Command::AdmitAuthority(_) | Command::AdmitRenewal(..),\n                AnchorOutcome::AuthorityCurrent')
f.write_text(s)

# Reuse the already committed real-target A/B counterexample. Its full native
# B recovery refusal remains mandatory; the experimental query adds a distinct
# A-current/B-denied check both before and after ACK.
f = p / 'src/enrollment/witness_renewal_tests.rs'
s = f.read_text()
needle = '    assert_eq!(admitted.observed_head(), proposal_b.target_head());'
s = replace(s, needle, needle + '''
    for (statement, expected) in [
        (a.statement_digest(), AnchorOutcome::AuthorityCurrent),
        (b.statement_digest(), AnchorOutcome::AuthorityDenied),
    ] {
        let exact = exchange(AnchorOperation::admit_renewal(
            b.successor_device().authority_binding(), statement).expect("exact authorization"));
        assert_eq!(exact.outcome(), expected);
        assert_eq!(exact.observed_head(), proposal_b.target_head());
    }
''', count=2)
f.write_text(s)

f = p / 'src/anchor/store.rs'
s = f.read_text()
s = replace(s, '    renewal_floor: u64,', '    renewal_authorization: Option<[u8; 32]>,\n    renewal_floor: u64,')
s = replace(s, '                renewal_floor: 0,', '                renewal_authorization: None,\n                renewal_floor: 0,')
s = replace(s, '            Command::CredentialCommit(_)\n', '''            Command::AdmitRenewal(authority, statement) => {
                let live = match entry.validity.check(now) {
                    Ok(()) => true,
                    Err(Error::Validity) => false,
                    Err(error) => return Err(error.into()),
                };
                if entry.authority == authority
                    && entry.renewal_authorization == Some(statement)
                    && live
                {
                    AnchorOutcome::AuthorityCurrent
                } else {
                    AnchorOutcome::AuthorityDenied
                }
            }
            Command::CredentialCommit(_)
''')
s = replace(s, '    let mut bytes = if cancellation {', '''    let exact_authorization = image.entries.values().any(|entry| entry.renewal_authorization.is_some());
    let mut bytes = if exact_authorization {
        b"QPANC005".to_vec()
    } else if cancellation {''')
s = replace(s, '        if joint {', '        if joint || exact_authorization {')
needle = '''        }
    }
    if bytes.len() + 32 > MAX_IMAGE {'''
s = replace(s, needle, '''        }
        if exact_authorization {
            bytes.push(u8::from(entry.renewal_authorization.is_some()));
            bytes.extend_from_slice(&entry.renewal_authorization.unwrap_or([0; 32]));
        }
    }
    if bytes.len() + 32 > MAX_IMAGE {''')
s = replace(s, '*b"QPANC003", *b"QPANC004"].contains(&version)', '*b"QPANC003", *b"QPANC004", *b"QPANC005"].contains(&version)')
s = replace(s, 'if version == *b"QPANC003" || version == *b"QPANC004" {', 'if [*b"QPANC003", *b"QPANC004", *b"QPANC005"].contains(&version) {')
s = replace(s, 'CredentialRenewalRecord::decode(&mut d, version == *b"QPANC004")?', 'CredentialRenewalRecord::decode(&mut d, version == *b"QPANC004" || version == *b"QPANC005")?')
s = replace(s, '            if id != subject.id(&pin.binding)', '''            let renewal_authorization = if version == *b"QPANC005" {
                let [present] = d.array()?;
                let statement = d.array()?;
                match present {
                    0 if statement == [0; 32] => None,
                    1 => { nonzero(&statement)?; Some(statement) }
                    _ => return Err(DurableError::Corrupt),
                }
            } else { None };
            if id != subject.id(&pin.binding)''')
s = replace(s, '                renewal_floor,\n', '                renewal_authorization,\n                renewal_floor,\n')
f.write_text(s)

f = p / 'src/anchor/store/renewal.rs'
s = f.read_text()
s = replace(s, '        if self.renewal_floor == 1', '''        if let Some(statement) = self.renewal_authorization {
            nonzero(&statement)?;
            if self.renewal_floor < 2 {
                return Err(DurableError::Corrupt);
            }
        }
        if self.renewal_floor == 1''')
s = replace(s, '                Phase::Applied\n                    if self.head == proposal.target', '''                Phase::Applied
                    if !self.renewal_authorization.is_some_and(|s| s != proposal.statement())
                        && self.head == proposal.target''')
s = replace(s, '                    self.credential_owner = record.owner;', '''                    self.renewal_authorization = Some(record.proposal.statement());
                    self.credential_owner = record.owner;''')
f.write_text(s)
