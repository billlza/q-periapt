# Apple Silicon independent control completion

The Apple Silicon [job 117715177429](https://github.com/billlza/q-periapt/actions/runs/39140980688/job/117715177429)
completes all seven lanes successfully at
`a6760a651c19ae481510ff7e7c87a6a4a702718a`. The Linux result for this same
commit was already captured in the adjacent hosted-control checkpoint. The
earlier observation that this job was queued remains a historical observation.
This result covers version-three control requests; it does not qualify the later
version-four outcome-resolution implementation.

The original artifact is 4,812,258 bytes with 1,884 members, SHA-256
`142cfa8b22aa501786420bc91b95bbca60471511712a306cb994eb37c7f50188`.
Two independent public readbacks complete without diagnostics, verifying all
40 source files against the committed Git objects and the actual ARM64 Mach-O
counterpart, SHA-256
`88d39f6c7d5e5870e8722c58672f0cf09b03dfdb209802d2867d02656973b2e5`.
The public helpers executed by these readers are also checked against that commit.

The control lane retains seven targets, 111 fresh-process operations, 80 native
commands, 13 real SIGKILL cuts, 101 control results and 33 unique signed controls.
Public replay checks original request/offer/receipt bytes, signatures, transcript
chains, worker PID/cut markers and command hashes. The six earlier lanes retain
their bootstrap, traffic, volatile/durable rekey, capacity and recovery checks.
Private codec and secret-key assertions remain actual runtime checks; the public
readers do not load private images or reconstruct their secrets.

`CAPTURE.zip` contains the exact downloaded artifact, both readers and outputs,
source files, download validation and terminal job metadata. Its manifest checks
every captured file: 3,828,307 bytes, 56 members, SHA-256
`046be7ceec3a17bee91b2f5576274d963411f69d8661d425d9d5f49017734f70`.
This checkpoint adds hosted Apple Silicon evidence, not a network carrier,
installed independent lifecycle, power-loss, physical-erasure or PCS claim.
