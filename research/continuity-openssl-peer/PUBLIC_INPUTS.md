# Public bootstrap input and original-context reconstruction

Status: independent reference boundary, not an installed account service or final
product interface. Callers supply their own separately trusted inputs; the API
has no dependency on the native test issuer or its filenames.

`peer.bootstrap_bundle.BootstrapBundle` reads and writes the existing native
[QPBNDL01 container](../continuity-identity-candidate/BOOTSTRAP_BUNDLE.md). Parsing
checks only canonical framing: at most 65,536 bytes, nine fields of at most 8,192
bytes, seven nonempty mandatory fields, and the exact optional-proof shape for
qualities 1–4. The independent implementation supports reusable-both quality 2.
Verification refuses a different required quality and explicitly refuses an
unimplemented quality; it never negotiates a fallback.

`verify(pins, sdk_document, sdk_signature, policy, now, required_quality=2, ...)`
returns the same authenticated context as the existing verifier. Account roots,
exact devices/generations, roster and policy checkpoints, SDK state, directory
expectation, required quality, witness pin and trusted time remain independent
inputs. None comes from the bundle. Parsing, signature verification and a context
snapshot do not enroll a device, update trust, install a roster, consume prekeys
or authorize application traffic. Account login and independent approval remain
host responsibilities.

## Reopening original state

`verify_original` additionally requires the original context digest retained by
the host and its actual current trusted time. It reconstructs the exact original
public snapshot even when its prekey advertisement or old credential has expired.
It does not ask a caller to supply a made-up old time or catch a failed current
verification and silently retry it as historical.

The method extracts bounded untrusted interval hints and selects the greatest
start of the policy, both credentials, both rosters and the selected leaves.
That instant cannot exceed the supplied current time. The unchanged ordinary
verifier then checks all signatures, exact pins, membership, policy/suite scope,
interval intersection and manifest/leaf containment at that instant. A hint is
never accepted as a signature, authority or permission. Finally the recomputed
context digest must equal the separately retained original expectation.

The resulting `Context` remains a public snapshot. Opening the original owner
must authenticate its existing journal and match its original scope and signer.
Every new bootstrap and ordinary operation still checks its supplied current
trusted time, retained current identity and any required witness. Expired inputs
cannot create a new journal or provision a new witnessed session. Missing active
storage is an error, not first use. Historical reconstruction does not extend a
credential, restore a revoked peer, substitute for renewal or construct a native
live policy/runtime owner. Native SDK owner invalidation is a separate contract.

The test worker now uses this original-input path with its retained scope digest
and each operation's trusted time. It no longer hard-codes time 150 to reopen
all original contexts. The fixture file adapter remains test infrastructure;
applications call the byte-oriented API with their own trust source.

## Verification

`public_input_checks.py` uses the unchanged native `import_bootstrap_bundle`
executable and independent Python/OpenSSL verifier against the same separately
supplied inputs. It exercises local and required-witness policies, exact context
agreement, every bundle truncation, field/total limits, proof-presence and quality
mismatch, all seven public-field mutations, a wrong original digest, future
snapshots and expired new-creation refusal. Native importer refusal must be exit 1
with an explicit error; crashes or missing executables do not count.

Existing session, rekey, renewal, revocation, unknown-outcome and pending-write
scenarios exercise the new worker reconstruction on their original private state.
This input boundary is a prerequisite for standalone enrollment and installation;
it does not itself qualify network deployment, independent account authentication,
whole-device lifecycle, physical erasure or post-compromise secrecy.
