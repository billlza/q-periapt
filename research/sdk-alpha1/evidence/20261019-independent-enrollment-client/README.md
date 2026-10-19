# Independent enrollment client checks

Local source `f0b861e2dcbafa4e4d5803363120354b31ccafff` adds a persistent
configuration coordinator and CLI for original device enrollment. It reuses the
existing encrypted journal and Registration owner; account authorization remains
external. The host retains the original client ID and wrapping key. No account
signup, private signing-key export or browser cookie is introduced.

A fresh wheel built from an ordinary immutable checkout was installed outside the
checkout. All 50 package modules, wheel metadata/licenses/RECORD and installed
bytes were verified before/after runtime. The installed adapter passed 8 checks;
the installed client passed 10 checks, with actual CLI subprocesses and 5 SIGKILL
cuts. No tests were skipped. The provider was cryptography48.0.1/OpenSSL4.0.1.

Three cuts recover the original device creation target, readiness target and
committed request. Two earlier cuts remain explicit failures: no formally
published original device intent means no discoverable original device. Recovery
does not recreate a signer or select an arbitrary orphan. Wrong keys/IDs, missing
active state, replacement authority and concurrent ownership are rejected. These
are component checks with fresh test issuers, not actual host-account approval.

The first source run had two wrong test expectations (`Provisioned` versus the
existing `Preparing` phase). The original failures and source snapshots are kept;
the repaired expectations preserve the existing contract. Source tests then
passed client10/adapter8, followed by the distinct installed-wheel run.

[Hosted run39212845634](https://github.com/billlza/q-periapt/actions/runs/39212845634)
checks the EARLIER source `128569f3be4824d0c07d0291097c1e74ae833c07` on Linuxx86_64
and AppleSilicon. Its terminal artifacts were verified against GitHub digests,
closed37-member inventories,63 Git-source inputs and the identical installed
48-module wheel. Both platforms passed adapter8, Node17 and Rust26 debug/release
entries (25 behavioral and1 dispatcher), formatting, strictClippy and build.
Those hosted results do not cover the newer client. No live CI logs were read.

The capture includes public logs, terminal metadata, both hosted archives,
source snapshots and the local inspected wheel. Private fixtures, wrapping keys,
account databases and client private images remain outside the capture. A public
manifest binds every member; no downloaded native executable was run.

Full session CLI integration, operational policy publication, real browser-to-client
authorization, the pre-publication first-use recovery transition and remaining
0.2.0 lifecycle/research/release requirements stay open. No physical-device rerun
or release-readiness claim is made by this receipt.
