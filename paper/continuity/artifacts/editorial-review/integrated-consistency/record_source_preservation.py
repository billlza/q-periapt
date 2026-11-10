#!/usr/bin/env python3
"""Record or verify the integrated manuscript's source-preservation comparison."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[4]
BASELINE = "c7581ebc21f5d080d90840c13b52c793bcac9317"
REPORT = OUT / "independent-review.md"
RECEIPT = OUT / "source-preservation.json"
PATTERNS = {
    "formal_statements": r"\\begin\{(theorem|lemma|proposition|corollary|definition|remark)\}(.*?)\\end\{\1\}",
    "proofs": r"\\begin\{(proof)\}(.*?)\\end\{\1\}",
    "display_environments": r"\\begin\{(equation\*?|align\*?|gather\*?|multline\*?)\}(.*?)\\end\{\1\}",
    "bracket_displays": r"\\\[.*?\\\]",
}
OLD_SENTENCE = "actual $S_1$ and uses the Reply core as its salt, giving"
NEW_SENTENCE = "actual $S_1$ and uses the 32-byte Reply-core digest $t_1$ as its salt, giving"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def baseline_bytes(path: str) -> bytes:
    return subprocess.check_output(["git", "show", BASELINE + ":" + path], cwd=ROOT)


def blocks(source: str, pattern: str) -> list[dict]:
    return [
        {
            "start_line": source.count("\n", 0, match.start()) + 1,
            "sha256": sha(match.group(0).encode()),
            "text": match.group(0),
            "start_offset": match.start(),
        }
        for match in re.finditer(pattern, source, re.S)
    ]


def collect() -> dict:
    inventory = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", BASELINE, "--", "paper/continuity"],
        cwd=ROOT, text=True,
    ).splitlines()
    paths = sorted(
        path for path in inventory
        if PurePosixPath(path).parent == PurePosixPath("paper/continuity")
        and path.endswith(".tex") and PurePosixPath(path).name != "joc-submission.tex"
    )
    require(len(paths) == 40, "Expected the reviewed 40 modular TeX inputs")
    totals = {
        name: {"baseline": 0, "integrated": 0, "identical": 0, "changed": 0}
        for name in PATTERNS
    }
    module_records = []
    changed_proofs = []
    for path in paths:
        old_bytes = baseline_bytes(path)
        new_bytes = (ROOT / path).read_bytes()
        old, new = old_bytes.decode(), new_bytes.decode()
        record = {
            "path": path,
            "baseline_sha256": sha(old_bytes),
            "integrated_sha256": sha(new_bytes),
            "baseline_bytes": len(old_bytes),
            "integrated_bytes": len(new_bytes),
            "whole_file_identical": old_bytes == new_bytes,
            "labels_identical": re.findall(r"\\label\{([^}]+)\}", old)
            == re.findall(r"\\label\{([^}]+)\}", new),
            "blocks": {},
        }
        for name, pattern in PATTERNS.items():
            before, after = blocks(old, pattern), blocks(new, pattern)
            require(len(before) == len(after), "Block count changed: " + path + ":" + name)
            comparisons = []
            for index, (left, right) in enumerate(zip(before, after), 1):
                equal = left["sha256"] == right["sha256"]
                comparisons.append({
                    "ordinal": index,
                    "baseline_start_line": left["start_line"],
                    "integrated_start_line": right["start_line"],
                    "baseline_sha256": left["sha256"],
                    "integrated_sha256": right["sha256"],
                    "identical": equal,
                })
                if name == "proofs" and not equal:
                    preceding = blocks(new[:right["start_offset"]], PATTERNS["formal_statements"])
                    labels = re.findall(r"\\label\{([^}]+)\}", preceding[-1]["text"])
                    statement_label = next(label for label in labels if label.startswith(("lem:", "thm:", "prop:", "cor:")))
                    require(left["text"].count(OLD_SENTENCE) == 1, "Expected unique salt sentence")
                    require(left["text"].replace(OLD_SENTENCE, NEW_SENTENCE) == right["text"], "Additional proof change found")
                    changed_proofs.append({
                        "path": path,
                        "statement_label": statement_label,
                        "baseline_sentence": OLD_SENTENCE,
                        "integrated_sentence": NEW_SENTENCE,
                        "single_sentence_substitution_accounts_for_complete_proof_diff": True,
                        **comparisons[-1],
                    })
            record["blocks"][name] = comparisons
            totals[name]["baseline"] += len(before)
            totals[name]["integrated"] += len(after)
            totals[name]["identical"] += sum(item["identical"] for item in comparisons)
            totals[name]["changed"] += sum(not item["identical"] for item in comparisons)
        module_records.append(record)
    whole_equal = sum(item["whole_file_identical"] for item in module_records)
    require(whole_equal == 38, "Expected exactly 38 unchanged complete modules")
    require(all(item["labels_identical"] for item in module_records), "A module label sequence changed")
    require(totals["formal_statements"] == {"baseline": 57, "integrated": 57, "identical": 57, "changed": 0}, "Formal statement preservation mismatch")
    require(totals["proofs"] == {"baseline": 52, "integrated": 52, "identical": 51, "changed": 1}, "Proof preservation mismatch")
    require(totals["display_environments"] == {"baseline": 60, "integrated": 60, "identical": 60, "changed": 0}, "Display environment preservation mismatch")
    require(totals["bracket_displays"] == {"baseline": 108, "integrated": 108, "identical": 108, "changed": 0}, "Bracket display preservation mismatch")
    require(changed_proofs[0]["statement_label"] == "lem:bootstrap-initial-origin", "Unexpected changed proof")
    source_paths = [
        "paper/continuity/artifacts/bootstrap/initial/source/research/continuity-identity-candidate/src/bootstrap.rs",
        "paper/continuity/artifacts/bootstrap/initial/source/research/continuity-identity-candidate/src/crypto.rs",
    ]
    source_records = []
    for path in source_paths:
        content = (ROOT / path).read_bytes()
        require(content == baseline_bytes(path), "Archived native source changed: " + path)
        source_records.append({"path": path, "sha256": sha(content), "matches_baseline": True})
    flat_path = "paper/continuity/joc-submission.tex"
    flat = (ROOT / flat_path).read_text()
    require(NEW_SENTENCE in flat, "Flattened submission lacks the integrated proof sentence")
    require(r"t_1=H_{\rm reply\text{-}core}(y_{\rm core})\in\{0,1\}^{256}" in flat, "Flattened submission lacks the digest definition")
    return {
        "baseline_commit": BASELINE,
        "scope": "40 modular manuscript sources; generated flattened submission counted separately",
        "module_count": len(paths),
        "whole_file_identical": whole_equal,
        "module_label_sequences_identical": True,
        "totals": totals,
        "display_total": {"baseline": 168, "integrated": 168, "identical": 168, "changed": 0},
        "changed_proofs": changed_proofs,
        "modules": module_records,
        "archived_native_sources": source_records,
        "flattened_submission": {
            "path": flat_path,
            "sha256": sha((ROOT / flat_path).read_bytes()),
            "contains_integrated_digest_definition_and_proof_sentence": True,
            "excluded_from_modular_counts_to_avoid_duplication": True,
        },
        "manual_source_correspondence": {
            "reply_core_boundary": "Reply prefix and ciphertext, ending before confirmation tag and outer signature",
            "salt": "Framed SHA3-256 under reply-core; exactly 32 bytes passed to schedule and derive",
            "bootstrap_info_labels": ["handshake-seed", "confirmation-responder", "confirmation-initiator"],
            "information_lengths": [62, 70, 70],
            "expand_row_lengths": [63, 71, 71],
            "result": "Integrated definitions agree with response_body, finish_initiator, schedule, derive, and the shared digest framing",
        },
    }


def report_text() -> str:
    return r"""# Independent review of the integrated bootstrap clarification

## Conclusion

The integrated manuscript precisely identifies the native bootstrap salt and its three KDF information strings. The change preserves all 57 formal statement blocks and all 168 displayed formula blocks from baseline `c7581ebc21f5d080d90840c13b52c793bcac9317`. Of 52 proof blocks, 51 remain byte-identical; the remaining proof changes one explanatory sentence identifying the salt as the 32-byte Reply-core digest.

The comparison covers the 40 modular TeX sources. Thirty-eight complete modules remain byte-identical. The two edited modules are `bootstrap-authentication.tex` and `bootstrap-initial-source.tex`. The generated `joc-submission.tex` contains the same integrated definitions and proof sentence and is counted separately to avoid duplicating the manuscript's statements and proofs. All 40 module label sequences are preserved.

## Exact formal-content preservation

| Content | Baseline | Integrated | Byte-identical | Changed |
| --- | ---: | ---: | ---: | ---: |
| Formal statement blocks: theorem, lemma, proposition, corollary, definition, remark | 57 | 57 | 57 | 0 |
| Displayed formula blocks: 60 equation/align environments and 108 bracket displays | 168 | 168 | 168 | 0 |
| Proof blocks | 52 | 52 | 51 | 1 |
| Complete modular source files | 40 | 40 | 38 | 2 |

`source-preservation.json` gives each module's baseline and integrated byte length and SHA-256, each formal/proof/display block's two hashes and locations, and the preserved label-sequence result. The unchanged displayed equations retain their hypotheses, residuals, and probability coefficients. The introductory paragraph adds the four inline equalities defining `t_1`, `I_s`, `I_R`, and `I_I`.

## The single proof change

The changed proof belongs to `lem:bootstrap-initial-origin` in `bootstrap-initial-source.tex`.

Baseline sentence:

```tex
actual $S_1$ and uses the Reply core as its salt, giving
```

Integrated sentence:

```tex
actual $S_1$ and uses the 32-byte Reply-core digest $t_1$ as its salt, giving
```

Substituting precisely that sentence in the baseline proof produces the complete integrated proof byte-for-byte. The proof's remaining text and displayed expressions are preserved.

## Native source correspondence

The archived `bootstrap.rs` and `crypto.rs` under `artifacts/bootstrap/initial/source/research/continuity-identity-candidate/src/` were inspected directly and remain identical to their baseline blobs.

- `response_prefix` and `response_body` build the Reply prefix and append its ciphertext. `response_body` computes the framed `reply-core` hash, calls `schedule` with that digest, and subsequently appends the responder confirmation tag. The outer signature is produced after this body is formed.
- `finish_initiator` reconstructs the same digest from exactly `body[..REPLY_CORE]`. This confirms the integrated definition's core boundary at both endpoints.
- `schedule` takes the digest as a 32-byte value; `derive` accepts `salt: &[u8; 32]` and passes it to HKDF Extract. The integrated `t_1` definition consequently supplies the salt type used by the compression-level entry equations.
- `derive` concatenates the 48-byte bootstrap KDF domain with the labels `handshake-seed`, `confirmation-responder`, and `confirmation-initiator`. Their complete information lengths are 62, 70, and 70 bytes; the corresponding one-block Expand messages remain 63, 71, and 71 bytes.
- `crypto.rs::digest_start` frames the domain and payload with their big-endian 64-bit lengths before SHA3-256. The integrated reference to the distinct framed source domain preserves this computation.

The integrated text therefore closes the specific byte-identity ambiguity recorded by the baseline consistency review. The existing joint-entry and bootstrap conclusions retain their formal statements and costs.

## Recalculation

The preserved comparison requires the baseline Git object and the integrated module bytes identified in `source-preservation.json`. Run:

```sh
python paper/continuity/artifacts/editorial-review/integrated-consistency/record_source_preservation.py --check
```

The check recomputes the historical-versus-integrated hashes, block comparisons, labels, exact proof substitution, and source correspondence input identities. It reads the saved report and receipt without rewriting them. `focused-checks.json`, `verification.json`, and the baseline audit receipts are preserved.
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Verify the recorded comparison without writing")
    options = parser.parse_args()
    result = collect()
    report = report_text()
    if options.check:
        saved = json.loads(RECEIPT.read_text())
        require(saved["comparison"] == result, "Integrated source snapshot differs from recorded comparison")
        require(REPORT.read_text() == report, "Independent review text differs from its retained source")
        require(saved["report_sha256"] == sha(REPORT.read_bytes()), "Independent review hash mismatch")
        require(saved["recalculation_script_sha256"] == sha(Path(__file__).read_bytes()), "Recalculation script hash mismatch")
    else:
        require(not REPORT.exists() and not RECEIPT.exists(), "Review outputs already exist; use --check")
        receipt = {
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "report_sha256": sha(report.encode()),
            "recalculation_script_sha256": sha(Path(__file__).read_bytes()),
            "comparison": result,
        }
        REPORT.write_text(report)
        RECEIPT.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({
        "status": "pass", "read_only_verification": options.check,
        "modules": 40, "whole_file_identical": 38,
        "formal_statements_identical": 57, "display_blocks_identical": 168,
        "proofs_identical": 51, "proofs_total": 52,
        "changed_proof": "lem:bootstrap-initial-origin",
    }))


if __name__ == "__main__":
    main()
