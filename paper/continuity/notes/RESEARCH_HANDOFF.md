# Q-Periapt JoC research checkpoint — 7 November 2026

## Current direction

The manuscript is **Exposure and Recovery with Persistent Randomness Reservations**, targeting Journal of Cryptology. Its continuous branch is `paper/joc-persistent-recovery`, with a dedicated draft pull request against `main`. Edit this manuscript and its directly used proof/evidence files through that branch. [WORKFLOW.md](WORKFLOW.md) records the build and update procedure.

The confirmed author is **Ziang Li (李子昂)**, Department of Engineering, Durham University. Correspondence: **2403871950@qq.com**. Alternative contact: **bhmq03@durham.ac.uk**. The current author list contains one person.

## Results completed in this revision

The prior origin-normalization, guarded record-exposure, private-image simulation, reverse-report composition and candidate-local accounting results remain in place. The new computation section adds:

1. **Lemma 5.9:** an exact HKDF block-table representation for adaptive complete information strings. Applied before the selected-seed Extract hop, it removes the parent row's internal input containing that seed.
2. **Theorem 5.10:** a joint shared-compression-oracle continuation from a uniform epoch root to the first message key of a designated fresh traffic allocation. Its finite M budget retains full-info aliases, zero-salt/session-salt aliases, real confirmation/ACK verification and successor-root/next-seed disclosure.
3. **Corollary 5.11 and the recovered-contribution entry:** the one-message AEAD reduction and the actual root Extract/Expand comparison, with their explicit score factors and complete query budgets.

The target material and direction are marked before that new material produces any blocks. Repeated complete information strings keep the same material identity. The network interface uses plaintext-free Resume; the honest application owns plaintext-bearing Send and delivery. The source profile records the same-ID guess-Send counterexample for an enlarged public caller interface. Existing eligibility and original-game projection accounting are preserved.

The full frozen proof and its 22-point cross-check are in [the joint-continuation artifact](../artifacts/joint-continuation/README.md). The [live profile](../artifacts/live-profile/source_profile.md) and source map bind actual constructors and observations to the declared experiment. Twenty-four inspected files are byte-identical at source pin `228c944fc476e3e57d6c08063cacb19bca5b360e` and development checkpoint `1c68aa666db22d36ee136be1ec712545a9e74f03`.

## Next research connection

Connect the **actual accepted ContextBound operation** to the theorem's **uniform recovered contribution** through one explicit chain of experiments:

1. Fix the accepted original generation/encapsulation pair using the retained offer/response, exact reservation identities and authoritative persistence history. Specify what the adapter returns on failed, repeated and unaccepted calls.
2. Embed the selected component challenge while preserving the same public operation and every exact retry. Cache the challenge by the original bound invocation, including the full retained offer and admitted policy/context.
3. Apply the ContextBound hidden-input hash comparison on its complete encoded tuple, with the preceding public/record view and all oracle work retained. Its uniform reply is the entry used by the new joint continuation.
4. Substitute those actual errors into the existing candidate-local accounting, retaining the native correspondence and the selected candidate's real projection residual at their established locations.

The notation distinguishes the random-component score `b_j` from the uniform-combined-contribution score `b_j^cont`. A valid complete ContextBound comparison with output-bit gap `epsilon_CB,j` costs `2 epsilon_CB,j` in the bounded score. The new schedule bound applies to `b_j^cont`; the explicit connecting inequality remains visible in the main text.

The first target is the marked first-message live profile already constructed in this revision. This gives a concrete intermediate proof to write and review. Broader retrospective target selection and additional application operations can then be treated as separately defined extensions.

## SkyBridge allocation

[skybridge-scope.md](skybridge-scope.md) reads the real SkyBridge original and later manuscripts. The JoC appendix now states their connection through authenticated transcript handling, operation admission and recovery release. SkyBridge's migration contract, forward-secrecy analysis, platform realization and migration experiments remain a coherent independent research line. The ContextBound substrate is from the earlier Q-Periapt binding manuscript and is identified separately.

## Validation identity

`integration_record.json` is the current local verification snapshot. It binds the PDF, single-file source, proof modules and source profile. The manuscript and exported source were compiled; finite-record checks were executed in an isolated build directory. Historical native, formal-model and reference-corpus evidence keeps its recorded source and execution dates. Remote workflow outcomes are attached to the dedicated PR's actual head commit.
