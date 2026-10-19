# Focused installed Android JNI public readback

[Run 39187630264](https://github.com/billlza/q-periapt/actions/runs/39187630264)
completed both debug and release partitions at
`893d15178af2915d02d667ee49b1c7b9aa2151c0`. Both upstream archives were checked
against their GitHub digests. Before/after manifests matched all 1132 committed
source files per profile; candidate source archives and packaged JARs were checked.

The original public readers rederived fixed/recoverable lifecycle, original
request/message recovery, local credential renewal and account outcomes, plus
native enrollment commitments. Each profile supplied all 430 required public
inputs. All 43 loaded reader sources matched the frozen Git commit. A separate
replay from this capture passed for both profiles without executing native code.

This closes the focused public-export/readback gap. Earlier missing-export
failures from the2328 cohort remain preserved. These new partitions are not
spliced into its older six-profile join and do not turn partial producer flags
into a full release claim.

The CI execution is macOS arm64 host JVM/JNI, not a fresh ART/emulator or physical
Android-device acceptance. Existing accepted physical-device evidence stays a
separate cohort. Signature verification remains native producer evidence; the
public replay is not an independent cryptographic verifier. The capture contains
complete selected public inputs, frozen readers, source crate, packaged JARs and
metadata. Full70MB upstream archives remain local rather than being duplicated
in Git. No private runtime state or native executables are included.
