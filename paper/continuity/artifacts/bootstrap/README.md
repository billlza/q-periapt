# Original-source bootstrap authentication

The manuscript connects original bootstrap reservations to historical responder
activation in `bootstrap-authentication.tex` and gives the shared-compression
entry comparison for either surviving contribution in `bootstrap-entry.tex`.
The first-result narrative and exact experiment appear in the manuscript;
this directory retains the complete source-level derivations and review trail.

## Proof and source packets

| Packet | Complete proof | Fixed source | Executable check |
|---|---|---|---|
| Joint short/long entry | `entry/proof.md` | `entry/SOURCE_PINS.json`, 7 files | `entry/check_entry.py` |
| Online terminal schedule | `terminal/proof.md`, `terminal/terminal-agreement.md` | `terminal/SOURCE_PINS.json`, 18 files | `terminal/check_connection.py` |
| Original reply source | `reply/proof.md` | `reply/SOURCE_PINS.json`, 32 files | `reply/check_source_adapter.py` |
| Manuscript composition | `integration-proof.md` and the two manuscript modules | `ack/SOURCE_PINS.json`, 19 message-source files | independent analytical review |

Each packet retains its original source bytes under `source/`, its original
`RESULT.json`, and the separate `reproduced.json`. Their source commits are
`b1cff2a045d23aecf75aef12122e5080a8419676`,
`360aa8107aa7df502108627a4dcf89f30d106594`, and
`68549dbc3ae4491d8b5edaa708548dc60743eab7`, respectively.
The ACK and message-interface census is pinned to
`471900bfe8070d1021a1feb67481437d599d80ba`.

Run `make -C paper/continuity check` from a full checkout. It verifies these
three retained source packets and writes separate receipts under `build/`.
The source-local commands, from `paper/continuity`, are:

```sh
python3 artifacts/bootstrap/entry/check_entry.py --source-root artifacts/bootstrap/entry/source --output build/bootstrap-entry.json
python3 artifacts/bootstrap/terminal/check_connection.py --source-root artifacts/bootstrap/terminal/source --output build/bootstrap-terminal.json
python3 artifacts/bootstrap/reply/check_source_adapter.py --source-root artifacts/bootstrap/reply/source --output build/bootstrap-reply.json
```

The finite checks cover exact compression/HMAC equations, source order and
token layouts, full-table coupling, original sample counts and endpoint
accounting. The general statements and reductions are in the proof notes and
manuscript. These checks retain the original execution identities of native
and symbolic evidence elsewhere in the paper.

## Independent review and composition

`independent-review_final.md` and `independent-review_final.json` bind the final
two manuscript modules. The review verified the source association, actual
restored-owner validation, two-endpoint capture terms, deferred root tables,
all activation blocks, ACK directions and the 107-byte authenticated string.

`integration-proof.md` supplies the final one-sided record-and-HMAC terminal
comparison. The explicit bootstrap/ACK operation surface is defined once in
the manuscript experiment. `independent-recommended_repair.md` and the initial
review retain the derivation that led to the corrected record treatment.
The source census also identifies the separate private-input interface needed
to add closure and fanout reports.

`formal-preservation.json` compares the exact ordered statement, proof and
display-math source of every preceding canonical module. Historical review
records remain under their original subject directories.

The independently reviewed initial-source SDK adapter is maintained in
`docs/continuity/BOOTSTRAP_INITIAL_SOURCE_ADAPTER_V1.md` on the integration
branch, with its source and review packet under
`research/sdk-alpha1/evidence/20261110-bootstrap-initial-source-adapter/`.
It supplies the complementary original-source construction; this manuscript
increment instantiates the reply-source profile and includes both primitive
short/long entry comparisons.

## Primary primitive sources

The ML-KEM encapsulation/correctness derivation uses FIPS 203 Algorithms
14, 15, 17 and 18, cited in the manuscript bibliography. The hidden-input and
joint-oracle costs use the existing `primitive-inputs.tex` and
`joint-primitive-bounds.tex` interfaces and their primary references. The fresh
encapsulation collision expression is derived in the manuscript from the
specified original 32-byte input and correctness event; it is not an empirical
collision estimate.
