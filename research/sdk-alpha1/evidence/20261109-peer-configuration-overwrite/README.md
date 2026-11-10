# Qualification-client ownership and path review

The peer-configuration consumer promises to overwrite every live caller buffer
between `prepare_configured` and `finish_open`. Ordinary `memset` leaves that
qualification observation vulnerable to dead-store elimination. The consumer
now performs volatile unsigned-character stores across the seven caller
allocations. These inputs are public test fixtures; the change preserves the
meaning of the ownership test.

The new C control includes the actual consumer and supplies an owned-copy model
and one borrowed-input model for each input region. At finish, it checks that
all caller bytes have changed, consumes either the retained copy or selected
caller bytes, and derives the model's result from the byte comparison. The
control runs 30 combinations across `-O0` and `-O3`, fresh/reopen constructors,
owned inputs and each individually borrowed region. All cases also execute the
existing guard-page checks. This is additional Unix harness evidence; native
SDK behavior continues to be established by the installed platform runs.

`VALIDATION.json` binds the current source, compiler and 20 passing tests.
`independent-review.json` records the separate source review and focused replay.
Raw regression output is retained beside them.

## Existing CodeQL review threads

The source pins below are recorded in `VALIDATION.json` against integration
commit `f16ad64034d3b0e784e20797aa19f046d22c91aa`.

| PR #121 thread | Source and observation | Disposition in this change |
| --- | --- | --- |
| `PRRT_kwDOTD-aVc608qrl` | `peer_configuration_client.c`: compiler-removable `memset` in the ownership qualification | Replace with volatile stores and retain optimized owned/borrowed controls. |
| `PRRT_kwDOTD-aVc608qrm` | `setup_client.c`: phase receipt path from `QPC_TEST_SYNC_LOG` | Retain as an explicitly reviewed local fault-harness input. |
| `PRRT_kwDOTD-aVc608qro` | `sync_probe.c`: journal selection from `QPC_TEST_SYNC_TARGET` | Retain as an explicitly reviewed local fault-harness input. |
| `PRRT_kwDOTD-aVc608qrq` | `sync_probe.c`: new receipt file from `QPC_TEST_SYNC_LOG` | Retain as an explicitly reviewed local fault-harness input. |

For the three path findings, `continuity_c_faults.Matrix` creates its private
work directory with mode 0700, discards inherited `LD_*`, `DYLD_*`, `QPC_TEST_*`
and `QPERIAPT_*` settings, and supplies exact target/receipt paths for each
owned invocation. `continuity_c_consumer` compiles the probe as a separate
test-process shared library and selects it explicitly for those invocations.
The harness principal already controls the executable and injected probe.
These path selections are part of that local qualification authority.

The journal and phase-receipt readers use no-follow opens followed by regular
file, uid, 0600-mode and single-link checks. The new receipt uses exclusive
creation and no-follow flags. These checks describe the reviewed invocation;
arbitrary environment-supplied paths are not introduced as an SDK interface.
The unchanged fault-harness tests verify inherited-environment removal,
selected executable/library identities, exact event accounting and error
propagation. Their successful execution is included in the 20-test receipt.

This review covers these four C findings. Other language categories retain
their separate analysis and alert status.
