# Active session-state disclosure counterexample

The authenticated whole-KEM control exercises one initial B session-state
disclosure followed by continuous active packet replacement. It is a
counterexample to interpreting a confirmed fresh epoch as evidence that an active
attacker has been removed. It is not an attack on the separate signed Continuity
identity/bootstrap candidate or a comparative claim about ML-KEM Braid or the
complete Triple Ratchet.

## Attacker and causal path

The attacker receives exactly one serialized B state before the first send. It
contains the initial root and both directional chain seeds, with no pending KEM
private key. One fork impersonates B towards A. A second fork swaps the disclosed
sending/receiving chains to impersonate A towards B. Subsequent attacker code
takes only public packets and its own RNG. It receives no later honest state,
message-key output, private KEM input or honest RNG state.

Each intercepted packet is authenticated and consumed on one attacker fork. The
other fork emits its own normal protocol packet, including fresh full ML-KEM
offers, ciphertexts and confirmations. Both honest endpoints generate real new
KEM material and advance normally. Their roots differ because the attacker
maintains two independent exchanges. On every step, the harness compares the
honest sender's actual message key with the attacker's receiving key, and the
attacker's sending key with the honest recipient's actual receiving key. Changing
the stolen authenticator makes the first real offer fail authentication.

No application AEAD, transport, persistence or device-identity signature layer is
executed here. Possession of both component message keys is the observed result.
The initial secret and deterministic RNG seeds remain public test fixtures.
Restricting attacker inputs tests causal derivation; it is not an unpredictability
game. Reports contain public packets and SHA-256 key commitments, never raw keys
or private snapshots.

## Observed fixed run

Each profile runs 512 alternating sends after the same disclosure cut:

| Update interval | Confirmed epochs A / B | Sender keys obtained by attacker | Different end-to-end keys | Packets with changed bytes |
| --- | ---: | ---: | ---: | ---: |
| 1 | 171 / 170 | 512 / 512 | 510 / 512 | 512 / 512 |
| 32 | 8 / 8 | 512 / 512 | 510 / 512 | 24 / 512 |
| 64 | 4 / 4 | 512 / 512 | 510 / 512 | 12 / 512 |

The first two messages use the disclosed initial chains. After the first KEM
transition, the honest endpoints use distinct attacker-known keys. An ordinary
no-control header can remain byte-identical while its message key differs;
counting changed headers alone therefore undercounts exposed keys. Three
wrong-authenticator negative controls cover all profiles.

`whole_kem_reference.py --active-fork` independently parses both public packet
streams and validates role/epoch/index sequencing, immutable control bodies,
public-key/ciphertext/confirmation bindings, all four per-event key commitments,
honest confirmation transitions and final accounting. Missing events, unknown
fields and an inflated interpretation fail. It does not recompute secrets from
public packets: actual cryptographic equality is checked inside the Rust execution
and bound to that source/test binary. Repeated debug/release output must match
byte-for-byte. The original corpora and fixed dependency locks are unchanged.

## Consequences for Continuity

The [Double Ratchet security considerations](https://signal.org/docs/specifications/doubleratchet/#recovery-from-compromise)
separate passive post-compromise recovery from continued active key substitution
and compromised identity/RNG state. This experiment establishes that counterexample
for this repository's whole-KEM control; it supplies no new general security theorem.

Product progress reports may expose confirmed epochs and pending work. They must
not emit an unconditional recovered status. The recovery argument must name which
session, pending-key, signing-key and RNG state was disclosed, when active
intervention stops, which fresh contributions remain unknown, and which deliveries
occur. If accountable rekey controls rely on an uncompromised device signer,
every transition must bind that independent authority and the exact
session/epoch/transcript. A MAC under a disclosed root cannot substitute for that
signature. Compromised identity authority requires independent device replacement
and revocation. The full hybrid composition and implementation remain required.

## Reproduce

Use new report paths; output files are created exclusively.

```sh
QPERIAPT_WHOLE_KEM_ACTIVE_REPORT="$PWD/target/whole-kem-active.json" \
  cargo test --manifest-path research/continuity-whole-kem-reference/Cargo.toml \
  --locked --release confirmed_fresh_epochs_do_not_end_continuous_active_session_impersonation -- --nocapture
sh artifact/python-run.sh artifact/whole_kem_reference.py \
  target/whole-kem-active.json --active-fork
```
