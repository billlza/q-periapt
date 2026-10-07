# Binding-model assumptions and semantic countermodels

The existing ContextBound prefix was compiled after truncating the development
before `op jrej`: its checked reductions do not need the later `zof_inj` and
`jrej_inj` comparison assumptions. The complete updated Makefile also compiled
BindingViaCR, MigrationBindingV2 and JRejectionCountermodel; all seven existing
proof-dependency controls and the two Continuity diagnostic models passed.
The native EasyCrypt binary reports the same source identity required by the
repository toolchain gate, which passed. These are model results, not a Rust
refinement, IND-CCA proof, or real ML-KEM/X-Wing/SHAKE attack.

The independent countermodel defines a constant 32-element rejection output and
an injective seed association. Three comparison games win with probability one,
while their corresponding encoded outer-hash inputs are equal. This demonstrates
that those comparisons cannot remove all rejection-function binding assumptions.
It does not show that global injectivity is necessary; a suitable computational
collision bound remains future proof work. No additional assumptions are declared
by the countermodel, and it does not import BindingViaCR's comparison axioms.

The declaration gate fixes seven assumptions and 59 named lemma statements in
the two binding files. Sixteen mutation/contract tests, the two affected workflow
tests and the extracted formal job's actionlint check passed. Definitions and
proof validity remain responsibilities of review and the mandatory compiler.
The proof source is under `formal/easycrypt`; raw tool logs are losslessly stored
as base64-encoded gzip with original lengths and SHA-256. The initial syntax and
redundant-tactic failures are retained separately, not relabeled as proof success.
