#!/usr/bin/env python3
"""Qualify sparse selection against the exact source tree and a local Git server."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

BASE = Path(__file__).resolve().parent
WORKTREE = BASE.parent / "codeql-checkout-fix"
tree = json.loads((BASE / "TREE.json").read_text())
workflow = (WORKTREE / ".github/workflows/codeql.yml").read_text()
block = workflow.split("          sparse-checkout: |\n", 1)[1]
patterns = []
for line in block.splitlines():
    if not line.startswith("            "):
        break
    patterns.append(line.strip())
assert patterns == ["/*", "!/research/sdk-alpha1/evidence/**/*.zip",
                    "/research/sdk-alpha1/evidence/**/"]
pattern_text = "\n".join(patterns) + "\n"

def git(root, *args, data=None):
    result = subprocess.run(["git", "-C", str(root), *args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout

def set_sparse(root):
    git(root, "config", "core.sparseCheckout", "true")
    git(root, "config", "core.sparseCheckoutCone", "false")
    (root / ".git/info/sparse-checkout").write_text(pattern_text)

rows = tree["blobs"]
paths = {r["path"] for r in rows}
omitted = {p for p in paths if p.startswith("research/sdk-alpha1/evidence/") and p.endswith(".zip")}
with tempfile.TemporaryDirectory(prefix="qperiapt-all-paths-") as temp:
    root = Path(temp)
    git(root, "init", "-q")
    empty_blob = git(root, "hash-object", "-w", "--stdin", data=b"").strip().decode()
    entries = b"".join(f'{r["mode"]} {empty_blob}\t{r["path"]}\0'.encode() for r in rows)
    git(root, "update-index", "-z", "--index-info", data=entries)
    fixture_tree = git(root, "write-tree").strip().decode()
    set_sparse(root)
    git(root, "read-tree", "--reset", "-u", fixture_tree)
    flags = git(root, "ls-files", "-t", "-z").decode().rstrip("\0").split("\0")
    observed_omissions = {record[2:] for record in flags if record.startswith("S ")}
    materialized = {p for p in paths if (root / p).is_file()}
    assert observed_omissions == omitted
    assert materialized == paths - omitted
    assert git(root, "write-tree").strip().decode() == fixture_tree
    assert all((bool((root / r["path"]).stat().st_mode & 0o111) == (r["mode"] == "100755"))
               for r in rows if r["path"] in materialized)
    full_tree_result = {
        "source_commit": tree["source_commit"], "source_tree": tree["tree_sha"],
        "scope": "real Git sparse matching over all exact tracked paths and modes, with empty fixture blobs",
        "tracked_files": len(paths), "omitted_files": len(omitted), "retained_files": len(materialized),
        "retained_rust_files": sum(p.endswith(".rs") for p in materialized),
        "omitted_non_zip_or_outside_prefix": len(observed_omissions - omitted),
        "original_tree_preserved": True,
        "tracked_bytes": sum(r["size"] for r in rows),
        "omitted_blob_bytes": sum(r["size"] for r in rows if r["path"] in omitted),
        "retained_blob_bytes": sum(r["size"] for r in rows if r["path"] in materialized),
    }

# A local upload-pack server proves filter negotiation and omitted blob absence.
with tempfile.TemporaryDirectory(prefix="qperiapt-partial-checkout-") as temp:
    root = Path(temp)
    origin, clone = root / "origin", root / "clone"
    origin.mkdir()
    git(origin, "init", "-q")
    kept = {
        "Cargo.toml": b"fixture manifest\n",
        "src/lib.rs": b"pub fn retained() {}\n",
        "artifact/codeql-summary-projection-plan.zip": b"retained capsule fixture\n",
        "research/sdk-alpha1/evidence/archive.zip/source.rs": b"retained nested source\n",
    }
    archived = {
        "research/sdk-alpha1/evidence/top.zip": b"omitted archive one\n",
        "research/sdk-alpha1/evidence/old/run.zip": b"omitted archive two\n",
    }
    for path, content in (kept | archived).items():
        output = origin / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
    git(origin, "add", "--all")
    git(origin, "-c", "user.name=月溅星河",
        "-c", "user.email=149552943+billlza@users.noreply.github.com",
        "commit", "-qm", "Isolated checkout qualification fixture")
    git(origin, "config", "uploadpack.allowFilter", "true")
    git(origin, "config", "uploadpack.allowAnySHA1InWant", "true")
    sha = git(origin, "rev-parse", "HEAD").strip().decode()
    tree_sha = git(origin, "rev-parse", "HEAD^{tree}").strip().decode()
    git(root, "clone", "--quiet", "--no-checkout", "--filter=blob:none", origin.as_uri(), str(clone))
    assert git(clone, "config", "--get", "remote.origin.promisor").strip() == b"true"
    assert git(clone, "config", "--get", "remote.origin.partialclonefilter").strip() == b"blob:none"
    set_sparse(clone)
    git(clone, "checkout", "--quiet", "--force", "--detach", sha)
    assert git(clone, "rev-parse", "HEAD").strip().decode() == sha
    assert git(clone, "rev-parse", "HEAD^{tree}").strip().decode() == tree_sha
    assert not git(clone, "status", "--porcelain")
    for path, content in kept.items():
        assert (clone / path).read_bytes() == content
    assert all(not (clone / path).exists() for path in archived)
    missing = {line[1:].decode() for line in git(clone, "rev-list", "--objects", "--missing=print", "HEAD").splitlines()
               if line.startswith(b"?")}
    archived_ids = {git(origin, "rev-parse", "HEAD:" + path).strip().decode() for path in archived}
    assert missing == archived_ids
    partial_clone_result = {
        "scope": "local upload-pack with filtering; no hosted wall-time inference",
        "filter": "blob:none", "promisor": True,
        "exact_commit_tree_preserved": True, "git_status_clean": True,
        "kept_files": len(kept), "omitted_files": len(archived),
        "omitted_blobs_unfetched": len(missing), "retained_bytes_equal": True,
    }
report = {"schema": 1, "patterns": patterns,
          "full_tree_matching": full_tree_result, "partial_clone": partial_clone_result,
          "workflow_sha256": hashlib.sha256((WORKTREE / ".github/workflows/codeql.yml").read_bytes()).hexdigest()}
(BASE / "CHECKS.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))

