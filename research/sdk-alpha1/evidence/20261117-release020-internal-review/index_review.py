"""Index the finite source review in REVIEW.md; do not infer release admission."""
import ast
import collections
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
inventory_bytes = (HERE / "INVENTORY.json").read_bytes()
inventory = json.loads(inventory_bytes)
SOURCE = inventory["source_commit"]
cache = {}


def source(path):
    if path not in cache:
        cache[path] = subprocess.check_output(["git", "show", SOURCE + ":" + path], cwd=ROOT)
    return cache[path]


def pin(path):
    data = source(path)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def scope(path, line):
    if not path.endswith(".py"):
        return None
    nodes = [node for node in ast.walk(ast.parse(source(path)))
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.lineno <= line <= node.end_lineno]
    if not nodes:
        return "module"
    node = min(nodes, key=lambda item: item.end_lineno - item.lineno)
    return {"function": node.name, "first_line": node.lineno, "last_line": node.end_lineno}


# These are the actual reviewed non-obvious test inclusion boundaries, not a
# rule that all source in a production-named file is safe.
TEST_GATES = {
    "bindings/rust/SDKPackageConsumer/src/lib.rs": "same file:4-5 cfg(test) module",
    "crates/q-periapt-ffi/src/lib.rs": "same file:1549-1550 cfg(test) module",
    "crates/q-periapt-host-store/src/filesystem.rs": "same file:576-577 redb_header_tests",
    "research/continuity-identity-candidate/src/anchor/store/handoff/import/testing.rs": "parent import.rs:15 cfg(all(test, unix))",
    "research/continuity-identity-candidate/src/connection_transport.rs": "same file:166-167 test_support",
    "research/continuity-identity-candidate/src/control_transport.rs": "same file:352-353 test_support",
    "research/continuity-identity-candidate/src/crypto/persistence/retirement/faults.rs": "parent retirement.rs:24 test-only module",
    "research/continuity-identity-candidate/src/durable/messages/rekey.rs": "same file:300 test-only after_effect",
    "research/continuity-identity-candidate/src/durable/write_intent/retired_cleanup/erasure.rs": "same file:228 test-only at_boundary",
    "research/continuity-identity-candidate/src/enrollment/account_root/process.rs": "account_root.rs:428 test module; tests.rs:18 explicit path",
    "research/continuity-identity-candidate/src/windows_key_reopen.rs": "lib.rs:125 cfg(all(test, windows))",
    "research/continuity-reference-app/src/enrollment.rs": "same file:182 cfg(test) marker function",
    "research/continuity-whole-kem-reference/src/main.rs": "same file:1062-1063 cfg(test) module",
}
OPERATORS = {
    "q-periapt-continuity-witness.rs": "Explicit local Witness database/trust/export selection; serving closes over the selected path and identity.",
    "q-periapt-native-device.rs": "Explicit local installation/key/trust/export selection; bounded private inputs and independent publication/policy pins.",
    "q-periapt-policy-publisher.rs": "Explicit publisher database, signed SDK inputs and exclusive private export directory.",
    "q-periapt-sdk-policy-authority.rs": "Explicit authority database, private policy input and exclusive private export directory.",
}
origins = {}


def origin(language, item):
    path, line = item["path"], item["line"]
    key = f"{language}:{path}:{line}"
    if key in origins:
        return key
    statement = source(path).decode().splitlines()[line - 1].strip()
    record = {"path": path, "line": line, "statement": statement}
    if language == "python-path":
        if not any(value in statement for value in ("sys.argv", "os.environ", "parse_args")):
            raise ValueError("unclassified Python path origin: " + key)
        if "/evidence/" in path:
            record["authority"] = "retained experiment operator CLI/environment; no hostile-invoker confinement claim"
        elif "/tests/" in path or "_worker.py" in path or "/test" in path:
            record["authority"] = "local qualification/test fixture and explicitly selected implementation/tool/configuration"
        else:
            record["authority"] = "explicit local input/output/tool capability; retain the distinct admission checks described in REVIEW.md"
    elif language == "rust-path-command":
        if path in TEST_GATES:
            record["authority"] = "test-only process/fixture capability"
            record["inclusion_boundary"] = TEST_GATES[path]
        elif path == "crates/q-periapt-mlkem-native-sys/build.rs":
            record["authority"] = "Cargo/explicit compiler selection and validated target metadata"
        elif "/src/bin/" in path and Path(path).name in OPERATORS:
            record["authority"] = OPERATORS[Path(path).name]
        elif any(value in path for value in ("/tests", "_tests", "/examples/", "/evidence/", "/artifacts/")):
            record["authority"] = "selected test/example/retained-source process and its local fixture inputs; not a remote application path selector"
        else:
            raise ValueError("unclassified Rust origin: " + key)
    else:
        raise ValueError(language)
    record["source_sha256"] = pin(path)["sha256"]
    origins[key] = record
    return key


KEY_NOTES = {
    ("crypto/persistence.rs", 66): "JournalKey::signing_owner_key full HKDF output before HMAC.",
    ("crypto/persistence.rs", 96): "Same complete signing-owner derivation for verification.",
    ("durable/messages/traffic.rs", 437): "step expands 64 bytes, copies the complete 32-byte message half before send AEAD.",
    ("durable/messages/traffic.rs", 524): "Receive step/retained message key is complete before AEAD; receiver floor/capacity checks remain.",
    ("durable/messages/tests.rs", 1629): "Adversarial disclosed-chain fixture uses the complete step-derived message key.",
    ("durable/messages/tests.rs", 1722): "Key-only replacement control uses complete step-derived fresh message key.",
    ("durable.rs", 1182): "JournalKey prepared by complete getrandom fill or exact QPVKEY01 decode before encryption.",
    ("durable.rs", 1229): "Same complete original JournalKey before decryption.",
    ("bootstrap.rs", 832): "SDK protocol export or complete derive HKDF output before confirmation MAC.",
    ("bootstrap.rs", 837): "Same completed confirmation key before verification.",
    ("durable/cancellation.rs", 348): "Complete 32-byte HKDF expansion with propagated failure precedes HMAC.",
    ("durable/messages/closure/archive.rs", 18): "Complete archive HKDF output before HMAC.",
    ("durable/messages/closure.rs", 91): "Fresh filled or fully decoded report key; absent sentinel remains None.",
    ("durable/messages/fanout/abandonment.rs", 101): "Fresh entropy fills the report key before retention and MAC.",
    ("durable/anchoring/tests.rs", 2026): "Authenticated-tampering test uses actual write_intent_key completed derivation.",
    ("durable/messages/rekey/completion.rs", 455): "Complete confirmation HKDF output before HMAC.",
    ("durable/messages/rekey/response.rs", 155): "Complete responder-confirmation HKDF output before HMAC.",
    ("durable/messages/resolution.rs", 188): "Fresh/retained complete key required; absent resolution_key returns State.",
    ("durable/messages/tests/send_budget.rs", 568): "Adversarial signed-close control completes HKDF before HMAC.",
    ("durable/messages/tests.rs", 1978): "Real-peer confirmation test completes HKDF before HMAC.",
    ("durable/retired_report/transferred/control/codec.rs", 12): "Complete domain-separated transferred-control key expansion before HMAC.",
    ("durable/retired_report.rs", 361): "Complete retired-report HKDF output before HMAC.",
    ("durable/tests.rs", 27): "Test helper uses completed witness_handoff_key derivation.",
    ("durable/tests.rs", 37): "Test helper uses completed account_root_fence_key derivation.",
    ("durable/write_intent/account_root.rs", 53): "Completed account_root_fence_key derivation before HMAC.",
    ("durable/write_intent/retired_cleanup/erasure.rs", 50): "Complete domain-separated erasure key expansion before HMAC.",
    ("durable/write_intent/witness_handoff/codec.rs", 20): "Completed witness_handoff_key derivation before HMAC.",
    ("durable/write_intent.rs", 388): "Completed write_intent_key derivation before HMAC.",
}
key_sinks = {}
rows = []
for language, analysis in inventory["analyses"].items():
    for result in analysis["results"]:
        rule, at = result["rule"], result["location"]
        path, line = at["path"], at["line"]
        row = {"result": f"{language}:{result['index']}", "rule": rule, "location": at,
               "status": "source_boundary_reviewed", "related_location_ids": [v["id"] for v in result["related"]]}
        if rule == "py/path-injection":
            row["review"] = "Python file paths and permissions"
            row["origins"] = [origin("python-path", item) for item in result["related"]]
        elif rule in ("py/code-injection", "py/command-line-injection"):
            row["review"] = "Python execution records"
            row["prior_review"] = "20261109-codeql-input-boundary-review plus critical-delta; current 24-origin bounded-command review"
        elif rule == "py/overly-permissive-file":
            row["review"] = "Python file paths and permissions"
            row["enclosing_scope"] = scope(path, line)
            if path in ("artifact/platform_distribution.py", "artifact/third_party_licenses.py"):
                row["disposition"] = "intentional public package/license file mode; not private transaction state"
            elif path.startswith("artifact/test_"):
                row["disposition"] = "temporary mode/identity negative control, public package fixture or actual-open wrapper"
            else:
                raise ValueError("unclassified permission result")
        elif rule in ("py/clear-text-storage-sensitive-data", "py/weak-sensitive-data-hashing"):
            row["review"] = "Python file paths and permissions"
            row["disposition"] = "explicit public synthetic negative/compatibility fixture"
        elif rule in ("rust/path-injection", "rust/command-line-injection"):
            row["review"] = "Rust file, command and diagnostic records"
            row["origins"] = [origin("rust-path-command", item) for item in result["related"]]
        elif rule in ("rust/log-injection", "rust/cleartext-logging"):
            row["review"] = "Rust file, command and diagnostic records"
            row["disposition"] = "test diagnostic/selected peer output, or public count/checkpoint/error; retain the scoped logging limits"
        elif rule == "rust/hard-coded-cryptographic-value":
            row["review"] = "Rust cryptographic values, allocations and pointers"
            if path == "crates/q-periapt-core/src/lib.rs" and line == 125:
                row["disposition"] = "zero-initialized storage filled before each named cryptographic use"
                row["key_sinks"] = []
                for item in result["related"]:
                    relative = item["path"].removeprefix("research/continuity-identity-candidate/src/")
                    note = KEY_NOTES[(relative, item["line"])]
                    key = f"{item['path']}:{item['line']}"
                    key_sinks[key] = {"path": item["path"], "line": item["line"], "disposition": note}
                    row["key_sinks"].append(key)
            elif path.endswith("/purpose.rs"):
                row["disposition"] = "public HKDF salt/domain; secret input retained"
            elif path.endswith("/bootstrap.rs") and line == 818:
                row["disposition"] = "complete getrandom fill with propagated failure before nonce return"
            elif path.endswith("/bootstrap.rs"):
                row["disposition"] = "known-answer vectors inside cfg(test) module"
            elif path.startswith(("research/continuity-spqr-reference/", "research/continuity-whole-kem-reference/")):
                row["disposition"] = "declared comparison-program public salt or deterministic fixture seed"
            elif path.startswith("services/q-periapt-policy-agent/src/"):
                row["disposition"] = "authority/IPC request/replay/adversarial test vector under test modules"
            else:
                raise ValueError("unclassified cryptographic result")
        elif rule in ("rust/access-invalid-pointer", "rust/uncontrolled-allocation-size"):
            row["review"] = "Rust cryptographic values, allocations and pointers"
            if path == "crates/q-periapt-host-store/src/windows_acl.rs":
                row["disposition"] = "owned OS allocation; descriptor/ACL validity and per-ACE bounds before reads"
            elif path == "services/q-periapt-policy-agent/src/activation_handoff.rs":
                row["disposition"] = "successful owned launchd array, non-null, count one, copy before free"
            elif path == "crates/q-periapt-ffi/examples/sdk_path_perf.rs":
                row["disposition"] = "both capacities bounded by main sample-count admission 100..=5000"
            else:
                raise ValueError("unclassified pointer/allocation result")
        elif rule == "cpp/path-injection":
            row["review"] = "C qualification paths and overall boundary"
            row["disposition"] = "explicit harness file capability, with private-file/inode checks and stated same-user boundary"
        else:
            raise ValueError("unclassified rule " + rule)
        rows.append(row)

if len(key_sinks) != 28 or len(rows) != 5012:
    raise ValueError("reviewed population changed")
for path, expected in inventory["location_source_pins"].items():
    if pin(path) != expected:
        raise ValueError("inventory source pin differs: " + path)
prior = json.loads((HERE.parent / "20261109-codeql-input-boundary-review/source-manifest.json").read_text())
comparisons = []
for item in prior["sources"]:
    if item["path"].endswith(".py"):
        current = pin(item["path"])
        comparisons.append({"path": item["path"], "prior_sha256": item["sha256"],
                            "selected_sha256": current["sha256"], "identical": current["sha256"] == item["sha256"]})
for path in (
    "research/continuity-identity-candidate/src/durable/messages.rs",
    "research/continuity-identity-candidate/src/durable.rs",
    "research/continuity-reference-app/src/operator_io.rs",
    "research/continuity-identity-candidate/src/identity.rs",
    "research/continuity-identity-candidate/src/lib.rs",
    "research/continuity-identity-candidate/src/enrollment/account_root.rs",
    "research/continuity-identity-candidate/src/enrollment/account_root/tests.rs",
    "research/continuity-identity-candidate/src/anchor/store/handoff/import.rs",
    "research/continuity-identity-candidate/src/crypto/persistence/retirement.rs",
    "services/q-periapt-policy-agent/src/lib.rs",
):
    source(path)
report = {
    "schema_version": 1, "kind": "qperiapt.release020_source_review_index", "source_commit": SOURCE,
    "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
    "review_sha256": hashlib.sha256((HERE / "REVIEW.md").read_bytes()).hexdigest(),
    "indexer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "all_recorded_results_have_source_disposition": True, "raw_result_count": len(rows),
    "distinct_path_command_origins": dict(collections.Counter(key.split(":", 1)[0] for key in origins)),
    "origins": origins, "key_sinks": key_sinks, "results": rows,
    "prior_python_source_comparison": comparisons,
    "source_pins": {path: pin(path) for path in sorted(cache)},
    "new_native_runtime_tests_performed_by_review": False,
    "final_release_source_and_analysis_reconciled": False,
    "release_claim_eligible": False, "publication_performed": False,
}
output = HERE / "DISPOSITIONS.json"
with output.open("x") as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write("\n")
print(json.dumps({"results": len(rows), "key_sinks": len(key_sinks),
                  "origins": report["distinct_path_command_origins"],
                  "final_release_source_and_analysis_reconciled": False}))
