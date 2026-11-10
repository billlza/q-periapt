# OpenSSL witness READY census

The independent OpenSSL server validator still required the QPCNET01 total of
142 after QPCNET02 added authenticated READY confirmation. The server generates
an epoch-zero acknowledgement and the client verifies it. Each operation reads
the authenticated journal image and checks its release fence, producing two
read-only Witness queries. The empty acknowledgement does not advance a message
floor or persist another image. One session therefore adds four queries.

The validator now uses the native TLS workload's exact expectation, 146, for
both the public report and every ordered negotiation record. Its independent
client scenario still requires two connections, each with exactly one exchange.
No historical archive, producer, protocol, security check or timeout changed.

Actual macOS Apple Silicon executions used the SDK archives produced at
`6084f3bfb09333f6b66291b38809ed512296a27b` by CI run `41791854684`, successful
job `126446831250`, artifact `13304914186`. The original package report and
every installed crate were checked against the current workspace. A fresh
Continuity candidate archive was built with the existing `package_candidate`
helper. The C library, C executable and Rust witness helper were built outside
the checkout from the extracted packages. The existing OpenSSL peer builder
checked its headers, CLI, runtime and linked libraries: OpenSSL 3.5.9.
Source, archive, compiler and executable hashes are retained.

| Selected actual scenario | Debug | Release |
| --- | --- | --- |
| OpenSSL server, installed C connection and revoked cleanup | 146 exchanges | 146 exchanges |
| OpenSSL client, native signed query and advance | two one-exchange connections | two one-exchange connections |
| Wrong subject, trailing data, missing end, wrong protocol | four refusals, zero store calls | four refusals, zero store calls |
| Native mutual TLS counterpart | 146 exchanges | 146 exchanges |

The original validator rejected both real server records. The repaired validator
accepted those same bytes and independently read back each public export.
The 24 focused Python regressions pass. Controls reject the old 142, missing or
extra exchanges, non-integer counts, report/trace disagreement, wrong role,
TLS version, group, ALPN and sequence. The red regression also demonstrates
that the original validator accepted a report and trace consistently using 142.

The diagnostic history is retained. The first Python invocation failed before
tests because its interpreter was not explicitly selected. Diagnostic attempt 01
used an exclusive JSON writer twice and stopped before product tests. Attempt 02
completed all three Debug OpenSSL scenarios, then the additional native TLS
test rejected an explicit `QPERIAPT_INSTALLED_CLIENT_LANGUAGE=C`; that fixture
requires the existing collector's absent-variable default for C. Attempt 03
rechecked the exact prepared sources and Debug exports, corrected only this
diagnostic environment, and completed the native Debug and all Release scenarios.
Attempt 02 remains a failed aggregate. No product assertion was weakened.

`CAPTURE.zip` contains 304 byte-verified members: the source patch and relevant
source snapshots, original and repaired readbacks, public exports, command
receipts, candidate archive and diagnostic failures. It excludes generated
private journals, wrapping/signing keys and TLS private keys. `MEMBERS.json`
pins every member; `VERIFICATION.json` gives the scope and archive digest.
The original SDK input ZIP remains in the adjacent CI audit evidence.

This closes the selected same-host Debug/Release installed regression. The TLS
implementation is independent; the Witness signature/state engine is shared.
It does not qualify the full installed package, another host, other platforms,
the current hosted CI wave or a formal 0.2.0 release. The corrected verifier is
identified by the retained source patch on the stated base, rather than being
silently attributed to that unmodified commit.
