# Witness account-root replacement

These local operator commands expose the existing native account-wide freeze,
replacement and permanent non-commit transactions. They use the original witness
database and key. They are separate from device replacement and from the TCP data
plane; incoming device requests cannot call them.

The host must independently authorize recovery of the application account and
select both roots, the successor device, policy and witness. An old-root signature
cannot authorize recovery from disclosure of that root. Retain the approved plan
in the application's original authority registry before invoking `root-freeze`.
The reference host can [prepare a candidate root](ROOT_PREPARATION.md), but its
HTTP service does not yet issue and cut over a successor root; these commands do
not complete that application lifecycle or add independent
Python client root replacement. The native
[managed owner](../continuity-identity-candidate/AUTHORITY_REPLACEMENT.md)
supplies the original registry, enrollment and journal coordination.

## Original inputs

Use the same absolute witness database and retained base64url witness identity
for every command. `--help` lists both ordinary and root operator arguments.
All JSON inputs use the existing bounded private-file reader. Outputs require an
existing empty private directory and use exclusive publication.

The independently selected trust file has schema
`qperiapt-witness-account-root-trust/1` and these fields:

- `operation` and `freeze_operation`: distinct nonzero 32-byte integer arrays,
  retained before the first call.
- `previous_root`: the original full hybrid public key in canonical unpadded
  base64url, selected through the trusted host authority channel.
- `successor`: the existing `qperiapt-witness-enrollment-trust/1` object, containing
  the independently approved account/root/roster, certificate, device, journal,
  genesis head and required-witness policy.

The separate successor preparation must match that trust exactly. The operator
checks the existing native plan, live successor credential and policy, and the
same witness pin. JSON bindings are correlation fields, not authorization.

## Plan, freeze and commit

Every line below has this prefix:

```text
q-periapt-continuity-witness <command> <absolute-host-db> <retained-witness-identity>
```

| Command | Remaining arguments | Result file |
| --- | --- | --- |
| `root-plan` | trust, successor preparation, output directory | `account-root-plan.json` |
| `root-freeze` | approved original plan, output directory | `account-root-freeze.json` |
| `root-bind` | same trust, preparation, plan, signed freeze, output directory | `account-root-decision.json` |
| `root-commit` | same trust, preparation, plan, freeze, decision, output directory | `account-root-outcome.json` |
| `root-status` | original decision, output directory | `account-root-outcome.json` |

Planning and binding are read-only. Freezing captures the original complete
witness snapshot and blocks both known and future unseen devices under the old
root. It does not enroll the successor or establish retirement. Binding verifies
the signed freeze and the exact originally selected target before producing the
decision. Commitment atomically retains account-wide retirement and enrolls that
target at the witness.

These witness operations do not themselves fence cached local client owners or
change the host's application-account association. The managed original registry
and client controller must perform those steps. Delayed replies issued before
freezing may still arrive. Preserve old session identities and unresolved delivery
accounting; root replacement does not transfer their secrets or infer delivery.

## Lost results and permanent closure

An error can follow a durable write or successful file publication. Keep the
original inputs and retry into a fresh output directory. Repeat `root-freeze`
with the same approved plan to recover its original snapshot. After an uncertain
commit, use `root-status` with the original bound decision. Status requires no
current target validity and returns `Unavailable`, `Committed` or `Closed`.
`Unavailable` does not prove non-commit. Terminal outcomes include signed native
historical proofs; they grant no current traffic permission. Recovered proof
signatures need not be byte-identical; their verified original statement is.

`root-close <decision> <output-directory>` permanently closes that original bound
operation. An already committed decision stays committed. For an operation that
has not been bound, `root-plan-close <plan> <output-directory>` returns the original
plan non-commit proof in `account-root-plan-outcome.json`. If it has already
committed, the command directs the operator to recover its bound decision status.
Plan and decision closure proofs have separate native verification purposes.

Closure never unfreezes an account or rolls back committed history. It cannot
cancel a freeze already in flight. An explicitly closed plan is refused before a
new freeze invocation. No error path generates a replacement key, chooses another
root, resets storage or restores old-root authority.

Native tests verify scope/refusal/receipt behavior and kill the operator process
after freeze, commitment and both closure boundaries. The separate
`tests/witness_root_operator.py` driver runs the actual CLI through commit,
decision-close and plan-close profiles, retaining public inputs, real BrokenPipe
outputs and original-key checks. The reference-account CI runs it using the
Release operator and native test helper. These are local operator observations;
full authenticated application cutover, independent clients, mobile lifecycle,
witness-key handoff and post-compromise security remain separate requirements.
