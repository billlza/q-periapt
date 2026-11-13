# Original-state program replacement with publication maintenance

This checkpoint qualifies one same-format installed-program edge on Apple Silicon:
the earlier SDK cohort and the new shared publication/maintenance implementation.
It exercises the original stores across real process replacement, including an
unresolved Witness mutation. It does not freeze a product version, promise
arbitrary rollback, qualify a legacy schema migration or establish power-loss
durability. No product code, format, assertion or timeout was changed.

| Installed native input | Candidate source | SDK producer | Executable SHA-256 |
| --- | --- | --- | --- |
| Before | `21e00e9c3cfd193b9f51491888347f583620dfe0` | `6084f3bfb09333f6b66291b38809ed512296a27b` | `c6af99c69f87f15f7c741ed97161b41c6b1673bae6ecc12f4ef4ea5a51e12b22` |
| After | `4effa8b2b25e7403ab912b65894a7d1e73695542` | `f560d803c43a24fff222daa5e5e5bd623bfdf874` | `eaf5e7cc305775b7d13292252dfba581bc797bca90be2a2b94d66ba2c2205254` |

Both are genuinely installed crate/SDK consumers built outside their source
checkouts. Their original build receipts, candidate archives, executable bytes
and relocation records remain unchanged. The SDK report hashes are respectively
`d9cd990bf3dc6a731ec09b659fdc38f3f3cbc17b2f035b09e5e61094cbc11885` and
`93fbef9dace1af6550a85095f6d2392285197a8fe589838f4d6f8447ba03c4f8`.
Each candidate archive has 767 members. Their differences are one document and
four test files; the shared SDK cohort carries the storage implementation change.
All 20 native fixture source/manifest inputs match between the two builds.

The source-bound controller at `0b75a2d16fcb8c5acf333cfa8cb88d837e5546de` installed
the independent wheel into a new outside-checkout directory. Wheel SHA-256 is
`596bba62781296558a64d768a12ed618043b8cf3e14070cdf81c2ed423d3a094`.
Both isolated `-I -S -B` probes import and hash all 105 product modules; the
private bytecode cache remains empty. CPython 3.14.10, cryptography 48.0.1 and
OpenSSL 4.0.1 are recorded. The provider's files are unchanged. No source-tree
protocol module replaces the installed package.

| Scenario | Native commands | Witness attempts | SIGKILL/re-exec cuts | Actual program switches |
| --- | ---: | ---: | ---: | ---: |
| Ordinary lifecycle | 328 | 219 | 10 | 9 |
| Mutation interrupted before dispatch | 345 | 230 | 11 | 10 |
| Mutation committed, signed reply withheld | 346 | 230 | 11 | 10 |

The three runs retain the original journal and 58 original key/identity/public
input file hashes at every cut. They perform 32 real process cuts and 29 switches:
15 forward and 14 backward over this exact same-format edge. Old PIDs exit with
`-9`; replacements use distinct PIDs and explicitly reopen the original approved
successor. Retired, unselected and wrong-target controls remain refused.

Original bootstrap responses, session identity, message ciphertext/plaintext,
acknowledgement and rekey results survive. Each scenario checks six exact replay
pairs, bidirectional communication and epoch-one traffic. The two uncertainty
cases retain the exact mutation target and command identity. Retried Witness
requests use a fresh challenge/signature, so their complete transport frames are
not asserted byte-identical. No backup is restored.

The fixture still combines the native peer and test Witness in one process,
using loopback communication, a test-control pipe and explicit synthetic clocks.
This is not an independently operated remote Witness or a physical device test.
The existing 900-second per-command bound remains; the three lifecycle commands
took 14.599, 18.283 and 17.262 seconds respectively.

## Preserved checker failure and independent readback

All three lifecycle commands and both import probes exited zero. The outer
driver then exited **1**: its final wheel-only inventory call incorrectly included
the separately copied test controllers. The original driver, traceback and
command receipts are retained. No `EXECUTION.json` was fabricated for that driver.

`READBACK.json` independently checks the exact union of 113 installed wheel files
and 101 registered application-side controller files, with no overlap or extra
file admitted. It then applies the unchanged strict wheel verifier to the exact
wheel subset and checks every separately recorded controller and provider hash.
This corrects the observation boundary without weakening the product verifier or
rerunning the lifecycle scenarios.

The runtime reader checks all 1,019 native commands, 679 Witness attempts, original
operation bytes, program selection records and the actual PID chain. Eighteen
altered-result/transcript controls are rejected. The same runtime reader then
passes directly over `CAPTURE.zip`; all 3,600 archive members are reread exactly.
Only explicitly selected transcripts, package/build inputs, controller sources
and receipts are captured. Private fixture directories, databases, wrapping-key
files and signing-key files are not copied.

`RESULT.json` and `FILES.json` bind the capture. Archive SHA-256 is
`63e68f58ed18a85813fe5af85eda9078c325f295c2c4644f05216a34f925b2f6`
(22,348,480 bytes). The earlier
[program-replacement checkpoint](../20261104-installed-program-upgrade/README.md)
retains its different source edge. This new result advances the
[upgrade contract](../../../../docs/continuity/UPGRADE_MAINTENANCE_V1.md) for the
maintenance cohort; foreign installers, other platforms, preview-state disposition,
final package/ABI admission, the computational proof and external review remain
separate work.
