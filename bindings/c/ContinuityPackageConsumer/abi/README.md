# Continuity C owner declaration contract

This declaration review began at package version `0.0.0`. The released
[0.2.0 Continuity C package](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-continuity-native-0.2.0-x86_64-unknown-linux-gnu.zip) uses `qpc-owner/1`.
The ordinary SDK retains its separate ABI 2 contract.
The snapshot covers all 158 exports, 70 C record types, the application callback
and 112 constants. The 70 names map to 69 native Rust record types: account and
session cleanup status deliberately share one implementation type.

`qpc-owner-v1.json` retains every declaration token, including parameter names,
array extents, pointer constness, record field order and constant values. Only
comments and whitespace may change without updating the reviewed snapshot.
Unrecognized preprocessing, attributes, added declarations and omitted
declarations fail the installed-package gate. A contract change requires an
explicit compatibility decision; regenerating this file is not that decision.

The Rust facade contains test-only field-type and complete function-pointer-type
assertions, plus exhaustive record patterns that reject fields added into padding.
Its single ABI test emits actual `size_of`, `align_of`, `offset_of`, field widths
and native type identities. A separately compiled C11 program uses the installed
header, retains references to every real export, links the installed sibling
library and reports the corresponding C observations. The collector requires
exact record/field inventories, equal complete layouts, and agreement between C
declarations and Rust function, callback and field types. No lifecycle calls are
made by the probe. Existing owner, cancellation, persistence, short-input and
error-output tests remain separate mandatory checks.

The comparison runs for both requested Debug/Release installed-consumer profiles
and is also wired into the Windows package consumer. Results establish only the
target actually compiled and executed. A 64-bit host result cannot qualify a
32-bit Android layout, an unexecuted platform, foreign callback behavior, storage
upgrades or full product admission. Signature/type agreement also cannot prove
that same-typed parameters have their documented meanings; lifecycle tests and
implementation review still supply that evidence.

The matching implementation is `artifact/continuity_c_abi.py`. Readback retains
the snapshot, header, compiler/test/probe/library identities and every layout.
The snapshot's `frozen_product_contract` remains false until the separate protocol,
storage, ownership, package and maintenance admission requirements are met.
