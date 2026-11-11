# Bootstrap terminal schedule connection: retained controls

Assessed repository commit:
`360aa8107aa7df502108627a4dcf89f30d106594`.

This packet accompanies
[`BOOTSTRAP_TERMINAL_SCHEDULE_CONNECTION_V1.md`](../../../../docs/continuity/BOOTSTRAP_TERMINAL_SCHEDULE_CONNECTION_V1.md).
The analytical result connects the opaque bootstrap-PRK service to U1's
ACK-only online class experiment. It permits later registration of an
unopened root-table handle, proves a compression-collision witness for
full-class descriptor aliases, and uses two comparisons to a common full
table to preserve the actual sibling distributions at both endpoints.

The retained conditional bound is

```text
epsilon_ACK|PRK <= D_0 + D_1 + chi_h(Q_h,0) + chi_h(Q_h,1),
```

clipped at one. The original component/disclosure realization remains the
separate `E_src,b` input stated in the proof. No wire format, native primitive,
storage format, implementation API or CI gate is changed by this packet.

## Reproduce

From a checkout containing the assessed source bytes and this packet:

```sh
python3 research/sdk-alpha1/evidence/20261109-bootstrap-terminal-schedule-connection/check_connection.py
```

For a separate exact source snapshot, supply `--source-root PATH`. To retain
a new result, add `--output PATH`. The checker uses only Python's standard
library, verifies every input against `SOURCE_PINS.json`, and fails on an
encoding, source-order, distribution or counterexample mismatch.

`RESULT.json` is the actual execution result retained on 9 November 2026.
Its checker and source-pin digests identify the evaluated files. The original
execution used the base source snapshot with `--source-root`; the original
implementation and proof inputs retain their exact Git-blob and SHA-256
identities in the 18-file source manifest.

## Executed controls

| Control | Retained outcome |
| --- | --- |
| Source order | Ten checks confirm complete Reply and root creation before activation, the two durable phase gates, one 160-byte Expand, and block-4 ACK use at both roles. |
| Exact public equations | 104-byte Final prefix; 93-byte root info; 111-byte activation info; activation HMAC message lengths 112/144/144/144/144. Synthetic full-wire aliases preserve the seed and produce their recorded distinct session/root/ACK outputs. |
| Deferred sampling | All 512 executions per sampling order have the same 114 available joint views. The enumeration includes 128 executions with numerically equal roots and 256 protected first activations. |
| Pre-registration leakage control | Selecting on an exposed root parity and then naively resampling changes one joint event probability from 0 to 1/4. The handle-independence premise detects this case. |
| Forced descriptor alias | One consistent finite compression oracle is deliberately assigned equal inner and outer pad states at two distinct session salts. Both root and all five activation outputs coincide; the recorded distinct inner-pad inputs give the collision witness. All 16 one-bit pad assignments also satisfy the alias-to-inner-collision implication. |
| Common-table endpoint | All 1,024 five-block tuples and 4,096 ACK-replacement executions have the same joint sibling/used-ACK distribution, with exact class reuse. |
| HKDF replacement boundary | Postprocessing block 4 leaves block 5 unchanged. Recomputing block 5 with the replacement ACK produces a distinct recorded value and is detected. |
| Retained-history stop | A captured, later deleted image remains in the recipe closure. The matching-key request stops before its return and preserves an earlier latched event; opening it before registration makes that class ineligible. |

The control wires are synthetic public inputs to the documented equations;
no signature verification or native provider run is represented by them.
The forced compression oracle is a deliberately constructed finite witness,
not an observed collision in SHA-256. The finite distribution checks exercise
the coupling and its counterexample; the document's general proof supplies
the interactive quantum statement.

## Contents

- `check_connection.py`: executable source, equation, finite-distribution and
  boundary controls.
- `SOURCE_PINS.json`: exact assessed source/proof inputs, including the
  bootstrap, durable activation and shared-oracle proof dependencies.
- `RESULT.json`: retained successful control execution.

The external collision input is Zhandry's Theorem 7 in *A Note on the Quantum
Collision and Set Equality Problems*, QIC 15(7–8), 557–567 (2015), checked in
the [primary text](https://www.rintonpress.com/xxqic15/qic-15-78/0557-0567.pdf),
page 562. Its universal-constant `C (q+2)^3/N` convention matches the existing
repository collision notation.
