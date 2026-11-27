# Manuscript revision status — 26 November 2026

The draft requires substantive revision following the assessment supplied on
26 November. The earlier statement that only final author approval remained
is withdrawn. Build success, retained check counts and internal review notes
do not settle the protocol, security-experiment and comparison questions
raised by that assessment.

## Results retained

The assessment reports that the checked key-schedule lemmas, component
reductions and candidate-local decomposition are sound under their stated
assumptions. It also reports consistent experimental numbers and authentic
bibliographic records. Those results and the original execution packets
remain part of the research record. This status note records the assessment;
it does not claim an additional proof audit.

The manuscript's online selected-message result has explicit source-selection,
signing-key and acquisition conditions. The draft also contains symbolic
results, finite checks and native executions. Each kind of evidence supports
its stated object and must be identified separately in the exposition.

## Issues raised for revision

1. **Protocol and experiment.** The paper needs a self-contained description of
   messages, state transitions, durable writes and adversarial oracles. The
   correspondence arguments must identify the invariant and transition cases
   used to connect these definitions to the protocol.
2. **Main theorem and contribution.** The executed-slot result gives the useful
   attribution bound. Its signing-key, original-reservation, record-acquisition
   and online-selection conditions determine the message guarantee. The
   relationship between the guarded-readability model and that computational
   guarantee needs an explicit account; acquisition and readability have
   different roles in the current development.
3. **Concrete bounds.** The multiplicative budgets, constants and idealized
   oracles need numerical instances. The general selector's attribution
   residual and the 192-bit sealing term affect which parameters give a
   nontrivial bound.
4. **Symbolic evidence.** The retained Tamarin result and completed dependencies
   must be distinguished from the unfinished multi-round existence witnesses
   and the separate finite checker. Model text and trace assumptions belong
   with the stated symbolic claim.
5. **Experiments.** The full native stack and component references have
   different services and capture interfaces. The existing runs describe
   those configurations. A claim comparing protocol performance requires
   matched services and adversary capabilities. All recorded schedules,
   retry-policy behavior and latency quantiles should be visible, with the
   deterministic nature of the current runs stated.
6. **Exposition and related work.** The principal construction and theorem
   should determine the manuscript structure. The reservation example needs
   to be placed against existing state-compromise models, and the choice to
   replay saved randomness needs comparison with discarding unused material
   and resampling where the protocol permits it.

These are the issues identified in the supplied review. Additional possible
research directions are not part of this revision list by default. No revised
submission date is asserted here.

## Declarations and approval

`declarations.tex` and `author-metadata.json` contain the current author,
funding, competing-interest and contribution information. The preparation
statement describes the recorded use of ChatGPT. Final submission approval
remains pending review of the assembled paper.

The review notes produced in the writing workflow are internal automated
checks. Their recorded assessments are not independent human peer review or
confirmation by the author. Source identities, proof arguments, executable
checks and verifier logs remain inspectable in the artifact directories.

## Entry points

- [Manuscript README](../README.md): source layout and build commands.
- [Research record](RESEARCH_HANDOFF.md): proof connections and recorded source
  interfaces.
- `integration_record.json`: document and execution identities for the build
  it records.
