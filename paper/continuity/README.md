# Persistent-randomness recovery manuscript

**Working title:** *Post-Compromise Security with Persistent Randomness Reservations*

**Research direction:** Journal of Cryptology first; ACM TOPS and TIFS are the subsequent venue options.

**Draft date:** 7 November 2026.

`main.tex` is the integrated manuscript. `continuity.pdf` is its checked reading copy.
The argument starts from a cryptographic question: how recovery depends on the
original reservation of randomness when a protocol can persist, replay, copy and
later disclose the state carrying that reservation.

## Results in the current draft

- The original-record model distinguishes reservation origin, first durable
  session-state save, physical image creation, acquisition and subsequent
  readability. Its alias-normalization lemma has a complete interface-level
  proof. The shared renderer preserves actual byte operations and oracle calls.
- The forbidden-acquisition corollary proves an eligible-event stopping rule
  using the existing target-session capture premise. Public record digests keep
  their ordinary rendering behavior.
- The retained multi-epoch Tamarin theorem and all 24 reusable dependencies are
  stated with their exact exposure conditions. The independent replay receipt,
  byte-identical certificate, native disclosure executions, finite ground
  traces and aggregate-copy evidence are linked to their source checkpoint.
- The adaptive origin-pair proposition gives and proves the unconditional
  centered-score accounting bound. It keeps each override world's adaptive
  target choice and charges usable-origin attribution separately.
- The evaluation reports the existing 28 configuration/schedule combinations
  and 336 endpoint-snapshot cases, together with the active whole-KEM control.
  A matched Continuity comparison is specified as the next experiment.

The concrete computational connection has two named inputs to discharge:
the protected-record/public-output adapter with source correspondence, and
the joint root/confirmation/traffic/ACK/successor-epoch bound. These inputs
are explicit in the accounting proposition. The model, interface proofs,
mechanized symbolic result and recorded executions stand on their respective
evidence.

## Source and build

The established protocol and experiment checkpoint is
`228c944fc476e3e57d6c08063cacb19bca5b360e`. Each historical execution retains its
own earlier source and tool receipt. Preparing this manuscript checked the
retained records; it did not rerun the long Tamarin or baseline experiments.
The appendix gives fixed repository links and the checked certificate digest.

From this directory, run:

```sh
make
```

This uses `latexmk`, pdfLaTeX and BibTeX. Intermediates go to
`../../target/continuity-paper/`; the resulting PDF is copied to `continuity.pdf`.
The November 7 build used TeX Live 2023 and latexmk 4.83. References, formula
layout, tables, the asynchronous trace figure and the rendered pages were
checked together.

## Editorial decisions

The paper states results positively and introduces their precise assumptions
where the theorem or comparison uses them. Related work credits SCKA's existing
future-epoch model and Triple Ratchet's retained-next-epoch analysis. The paper's
specific focus is persistent reservation provenance, record acquisition and
later readability, and their role in a recovery experiment.

The software release and research manuscript have separate completion criteria.
The new computational proof connections and matched research comparisons do not
add gates to the agreed 0.2.0 product release.
