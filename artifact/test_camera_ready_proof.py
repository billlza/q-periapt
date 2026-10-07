from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import unittest

from camera_ready_proof import (
    BUNDLE_ARTIFACTS,
    EXPECTED_TOOLS,
    TranscriptError,
    MAX_MEASURED_BINARY_BYTES,
    _archive_files,
    _capture_metadata_bytes,
    _canonical_summary_bytes,
    _parse_measurements_tsv,
    _freeze_binary,
    validate_netem_bytes,
    verify_file,
    verify_text,
)
from claim_ledger import canonical_tree_digest, repository_paths


RECORDED_AT = "2026-07-10T00:00Z"
RUN_ID = "0123456789abcdef0123456789abcdef"
HOST_UNAME = "Linux 6.8.0 x86_64"
CPU_NAME = "test cpu"
PIN = "4-5"
RUNNER_USER = "qperiapt-camera"
RUNNER_UID = 999
RUNNER_GID = 999
RUSTC_VERSION = "rustc 1.96.0 (test)"
CARGO_VERSION = "cargo 1.96.0"
CC_VERSION = "cc 1.0"
VALGRIND_VERSION = "valgrind-3.25.0"
ALPHA_CHECKSUM = "a" * 64
BETA_CHECKSUM = "b" * 64


def cargo_lock() -> bytes:
    return f'''version = 4

[[package]]
name = "alpha"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{ALPHA_CHECKSUM}"

[[package]]
name = "beta"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{BETA_CHECKSUM}"
'''.encode()


def cargo_seed_manifest() -> bytes:
    return (
        "path\tsize\tsha256\n"
        f"registry/cache/index.crates.io-test/alpha-1.0.0.crate\t101\t{ALPHA_CHECKSUM}\n"
        f"registry/cache/index.crates.io-test/beta-2.0.0.crate\t202\t{BETA_CHECKSUM}\n"
    ).encode()


def tuning_records() -> tuple[bytes, bytes]:
    records = [
        ("sysctl", "net.ipv4.tcp_tw_reuse", "2", "1"),
        ("sysctl", "net.ipv4.ip_local_port_range", "32768 60999", "1024 65535"),
        ("sysctl", "net.ipv4.tcp_fin_timeout", "60", "3"),
        (
            "sysfs",
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor",
            "powersave",
            "performance",
        ),
        ("sysfs", "/sys/devices/system/cpu/cpufreq/boost", "1", "0"),
    ]
    active = "kind\tname\tbefore\tactive\n" + "".join(
        f"{kind}\t{name}\t{before}\t{value}\n"
        for kind, name, before, value in records
    )
    after = "kind\tname\tbefore\tactive\tafter\n" + "".join(
        f"{kind}\t{name}\t{before}\t{value}\t{before}\n"
        for kind, name, before, value in records
    )
    return active.encode(), after.encode()


def run_git(root: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(
        ["/usr/bin/git", *args], cwd=root, text=True
    ).strip()


def measurement_tsv() -> bytes:
    lines = ["delay_ms\trep\tgroup\tp50_us\tp90_us\tp99_us\tp999_us"]
    for delay, repetitions in ((0, 20), (10, 6), (25, 4)):
        for rep in range(1, repetitions + 1):
            for group in ("classical", "standard", "bound", "compat"):
                lines.append(f"{delay}\t{rep}\t{group}\t1.0\t2.0\t3.0\t4.0")
    return ("\n".join(lines) + "\n").encode()


class CaptureFixture:
    def __init__(self, base: pathlib.Path) -> None:
        self.root = base / "repo"
        self.bundle = base / "bundle"
        self.root.mkdir()
        (self.root / "artifact").mkdir()
        (self.root / "paper").mkdir()
        (self.root / "input.txt").write_text("execution input\n", encoding="utf-8")
        (self.root / "artifact" / "results.json").write_text("{}\n", encoding="utf-8")
        (self.root / "paper" / "camera-ready-results.txt").write_text(
            "historical\n", encoding="utf-8"
        )
        (self.root / "Cargo.lock").write_bytes(cargo_lock())
        subprocess.run(["/usr/bin/git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(
            ["/usr/bin/git", "config", "user.email", "camera@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["/usr/bin/git", "config", "user.name", "Camera Test"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(["/usr/bin/git", "add", "."], cwd=self.root, check=True)
        subprocess.run(
            ["/usr/bin/git", "commit", "-q", "-m", "capture source"],
            cwd=self.root,
            check=True,
        )
        self.commit = run_git(self.root, "rev-parse", "HEAD")
        self.source_digest = canonical_tree_digest(
            self.root, repository_paths(self.root)
        )
        self.archive = subprocess.check_output(
            ["/usr/bin/git", "archive", "--format=tar", self.commit], cwd=self.root
        )
        self.archive_hash = hashlib.sha256(self.archive).hexdigest()
        self.tools = {
            name: (f"{index:064x}", f"/usr/bin/{name}")
            for index, name in enumerate(sorted(EXPECTED_TOOLS), start=1)
        }
        self.memcheck = {
            "control": 7,
            "ml-kem-ek": 17,
            "ml-kem-wholedk": 17,
            "ml-kem-probe": 0,
            "leaky-control": 9,
        }
        self.artifact_data = self._artifact_data()
        self.manifest_data = self._manifest_data()
        (self.bundle / "manifest.json").write_bytes(self.manifest_data)
        self.manifest_hash = hashlib.sha256(self.manifest_data).hexdigest()

    def _artifact_data(self) -> dict[str, bytes]:
        self.bundle.mkdir()
        measurements = measurement_tsv()
        rows = _parse_measurements_tsv(measurements)
        qdisc_baseline = b'[{"kind":"noqueue","root":true}]\n'
        qdisc_10 = json.dumps(
            [
                {
                    "kind": "netem",
                    "handle": "51ab:",
                    "root": True,
                    "options": {"limit": 1000, "delay": 10000},
                }
            ],
            separators=(",", ":"),
        ).encode()
        qdisc_25 = qdisc_10.replace(b"10000", b"25000")
        tool_lines = [
            f"tool-sha256: {name} {digest} {path}"
            for name, (digest, path) in self.tools.items()
        ]
        active_tuning, after_tuning = tuning_records()
        seed_manifest = cargo_seed_manifest()
        capture_metadata = _capture_metadata_bytes(
            host_uname=HOST_UNAME,
            cpu=CPU_NAME,
            recorded_at=RECORDED_AT,
            pin=PIN,
            reps=20,
            runner_user=RUNNER_USER,
            runner_uid=RUNNER_UID,
            runner_gid=RUNNER_GID,
            rustc_version=RUSTC_VERSION,
            cargo_version=CARGO_VERSION,
            cc_version=CC_VERSION,
            valgrind_version=VALGRIND_VERSION,
            tuning_active_data=active_tuning,
            tuning_after_data=after_tuning,
            qdisc_baseline_data=qdisc_baseline,
            qdisc_after_data=qdisc_baseline,
            cargo_seed_manifest_data=seed_manifest,
            lock_data=cargo_lock(),
        )
        data = {
            "source_archive": self.archive,
            "measurements": measurements,
            "summary": _canonical_summary_bytes(rows),
            "tool_hashes": ("\n".join(tool_lines) + "\n").encode(),
            "qdisc_baseline": qdisc_baseline,
            "qdisc_10ms": qdisc_10,
            "qdisc_25ms": qdisc_25,
            "netem_build_log": b"Finished release build\n",
            "ct_build_log": b"Finished release build\n",
            "memcheck_control": b"==1== ERROR SUMMARY: 7 errors from 7 contexts\n",
            "memcheck_mlkem_ek": b"==2== ERROR SUMMARY: 17 errors from 2 contexts\n",
            "memcheck_mlkem_wholedk": b"==3== ERROR SUMMARY: 17 errors from 2 contexts\n",
            "memcheck_mlkem_probe": b"==4== ERROR SUMMARY: 0 errors from 0 contexts\n",
            "memcheck_leaky_control": b"==5== ERROR SUMMARY: 9 errors from 9 contexts\n",
            "netem_binary": b"netem binary",
            "mlkem_ct_binary": b"mlkem binary",
            "leaky_control_ct_binary": b"synthetic leaky-control binary",
            "capture_metadata": capture_metadata,
            "cargo_seed_manifest": seed_manifest,
            "tuning_active": active_tuning,
            "tuning_after": after_tuning,
            "qdisc_after": qdisc_baseline,
        }
        self.binary_hashes = {
            "netem": hashlib.sha256(data["netem_binary"]).hexdigest(),
            "mlkem": hashlib.sha256(data["mlkem_ct_binary"]).hexdigest(),
            "leaky_control": hashlib.sha256(
                data["leaky_control_ct_binary"]
            ).hexdigest(),
        }
        for key, path in BUNDLE_ARTIFACTS.items():
            (self.bundle / path).write_bytes(data[key])
        return data

    def _manifest_data(self) -> bytes:
        artifacts = {
            key: {
                "path": path,
                "sha256": hashlib.sha256(self.artifact_data[key]).hexdigest(),
                "size": len(self.artifact_data[key]),
            }
            for key, path in BUNDLE_ARTIFACTS.items()
        }
        manifest = {
            "schema_version": 3,
            "kind": "qperiapt-camera-ready-capture",
            "run_id": RUN_ID,
            "recorded_at": RECORDED_AT,
            "commit": self.commit,
            "execution_input_sha256": self.source_digest,
            "source_archive_sha256": self.archive_hash,
            "netem_runs": 120,
            "ct_mode": "native",
            "generated_evidence_exclusions": [
                "artifact/results.json",
                "paper/camera-ready-results.txt",
            ],
            "artifacts": artifacts,
        }
        return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def transcript(self) -> str:
        seed_hash = hashlib.sha256(self.artifact_data["cargo_seed_manifest"]).hexdigest()
        lines = [
            "================ Q-Periapt camera-ready bare-metal ================",
            f"host : {HOST_UNAME}    date: {RECORDED_AT}",
            f"cpu  : {CPU_NAME}",
            f"pin  : cores {PIN}   reps: 20   supervisor: root   "
            f"runner-user: {RUNNER_USER}   runner-uid: {RUNNER_UID}   "
            f"runner-gid: {RUNNER_GID}   no-new-privs: yes   cgroup-v2: yes",
            f"commit: {self.commit}",
            f"source-tree-sha256: {self.source_digest}   dirty: false",
            f"source-archive-sha256: {self.archive_hash}",
            f"run-id: {RUN_ID}",
            f"cargo-seed: packages=2 files=2 manifest-sha256={seed_hash}",
            f"bundle-manifest-sha256: {self.manifest_hash}",
            "rustc:",
            RUSTC_VERSION,
            f"cargo: {CARGO_VERSION}",
            f"cc: {CC_VERSION}",
            f"valgrind: {VALGRIND_VERSION}",
        ]
        lines.extend(
            f"tool-sha256: {name} {digest} {path}"
            for name, (digest, path) in self.tools.items()
        )
        lines.append(f"netem-binary-sha256: {self.binary_hashes['netem']}")
        for delay, rtt, repetitions in ((0, 0, 20), (10, 20, 6), (25, 50, 4)):
            lines.append(f"== one-way={delay} ms (RTT={rtt} ms), reps={repetitions} ==")
            for rep in range(1, repetitions + 1):
                for group in ("classical", "standard", "bound", "compat"):
                    lines.append(
                        f"rep{rep:<2} {group:<10}     p50 = 1.0  p90 = 2.0  p99 = 3.0  p99.9 = 4.0"
                    )
        lines.extend(
            [
                "netem matrix complete: 120/120 group-runs",
                f"mlkem-ct-binary-sha256: {self.binary_hashes['mlkem']}",
                "leaky-control-ct-binary-sha256: "
                f"{self.binary_hashes['leaky_control']}",
                "  control:           ERROR SUMMARY: 7 errors from 7 contexts",
                "negative control OK: 7 errors",
                "  ml-kem-ek:         ERROR SUMMARY: 17 errors from 2 contexts",
                "  ml-kem-wholedk:    ERROR SUMMARY: 17 errors from 2 contexts",
                "  ml-kem-probe:      ERROR SUMMARY: 0 errors from 0 contexts",
                "  leaky-control:     ERROR SUMMARY: 9 errors from 9 contexts",
                "DISCRIMINATOR HOLDS: ML-KEM probe=0 vs planted secret branch=9",
                "provenance recheck: commit/source/archive/tools/binaries/cargo-seed unchanged",
                "CAMERA_READY_BARE_METAL_PASS "
                f"netem_runs=120 ct_mode=native commit={self.commit} "
                f"source_sha256={self.source_digest} archive_sha256={self.archive_hash} "
                f"netem_sha256={self.binary_hashes['netem']} "
                f"mlkem_ct_sha256={self.binary_hashes['mlkem']} "
                "leaky_control_ct_sha256="
                f"{self.binary_hashes['leaky_control']} run_id={RUN_ID} "
                f"bundle_manifest_sha256={self.manifest_hash}",
            ]
        )
        return "\n".join(lines) + "\n"

    def rewrite_artifact(self, key: str, data: bytes) -> None:
        (self.bundle / BUNDLE_ARTIFACTS[key]).write_bytes(data)

    def transcript_for_manifest(self, manifest_data: bytes) -> str:
        (self.bundle / "manifest.json").write_bytes(manifest_data)
        return self.transcript().replace(
            self.manifest_hash, hashlib.sha256(manifest_data).hexdigest()
        )

    def rewrite_bound_artifact(self, key: str, data: bytes) -> str:
        self.rewrite_artifact(key, data)
        manifest = json.loads(self.manifest_data)
        manifest["artifacts"][key]["sha256"] = hashlib.sha256(data).hexdigest()
        manifest["artifacts"][key]["size"] = len(data)
        manifest_data = (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        return self.transcript_for_manifest(manifest_data)


class CameraReadyProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = CaptureFixture(pathlib.Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_complete_source_and_raw_bundle_pass(self) -> None:
        verify_text(
            self.fixture.root,
            self.fixture.transcript(),
            self.fixture.bundle,
        )

    def test_evidence_only_successor_commit_passes(self) -> None:
        result = self.fixture.root / "artifact" / "results.json"
        result.write_text('{"capture":"recorded"}\n', encoding="utf-8")
        subprocess.run(["/usr/bin/git", "add", str(result)], cwd=self.fixture.root, check=True)
        subprocess.run(
            ["/usr/bin/git", "commit", "-q", "-m", "record evidence"],
            cwd=self.fixture.root,
            check=True,
        )
        verify_text(self.fixture.root, self.fixture.transcript(), self.fixture.bundle)

    def test_dirty_named_generated_evidence_passes(self) -> None:
        result = self.fixture.root / "artifact" / "results.json"
        result.write_text('{"capture":"not-yet-committed"}\n', encoding="utf-8")
        verify_text(self.fixture.root, self.fixture.transcript(), self.fixture.bundle)

    def test_execution_input_successor_commit_fails(self) -> None:
        source = self.fixture.root / "input.txt"
        source.write_text("changed\n", encoding="utf-8")
        subprocess.run(["/usr/bin/git", "add", str(source)], cwd=self.fixture.root, check=True)
        subprocess.run(
            ["/usr/bin/git", "commit", "-q", "-m", "change input"],
            cwd=self.fixture.root,
            check=True,
        )
        with self.assertRaisesRegex(TranscriptError, "execution inputs|successor commit"):
            verify_text(self.fixture.root, self.fixture.transcript(), self.fixture.bundle)

    def test_dirty_untracked_execution_input_fails(self) -> None:
        (self.fixture.root / "untracked.txt").write_text("input\n", encoding="utf-8")
        with self.assertRaisesRegex(TranscriptError, "current execution inputs"):
            verify_text(self.fixture.root, self.fixture.transcript(), self.fixture.bundle)

    def test_mode_only_execution_input_change_fails(self) -> None:
        source = self.fixture.root / "input.txt"
        source.chmod(0o755)
        with self.assertRaisesRegex(TranscriptError, "working tree changes execution inputs"):
            verify_text(self.fixture.root, self.fixture.transcript(), self.fixture.bundle)

    def test_tampered_binary_fails(self) -> None:
        self.fixture.rewrite_artifact("netem_binary", b"forged")
        with self.assertRaisesRegex(TranscriptError, "artifact (size|hash) mismatch"):
            verify_text(self.fixture.root, self.fixture.transcript(), self.fixture.bundle)

    def test_extra_bundle_member_fails(self) -> None:
        (self.fixture.bundle / "unexpected.txt").write_text("extra", encoding="utf-8")
        with self.assertRaisesRegex(TranscriptError, "too many top-level entries"):
            verify_text(self.fixture.root, self.fixture.transcript(), self.fixture.bundle)

    def test_bundle_root_symlink_fails(self) -> None:
        alias = pathlib.Path(self.temp.name) / "bundle-alias"
        alias.symlink_to(self.fixture.bundle, target_is_directory=True)
        with self.assertRaisesRegex(TranscriptError, "bundle path must not be a symlink"):
            verify_text(self.fixture.root, self.fixture.transcript(), alias)

    def test_transcript_symlink_fails(self) -> None:
        transcript = pathlib.Path(self.temp.name) / "transcript.txt"
        transcript.write_text(self.fixture.transcript(), encoding="utf-8")
        alias = pathlib.Path(self.temp.name) / "transcript-alias.txt"
        alias.symlink_to(transcript)
        with self.assertRaises((TranscriptError, OSError)):
            verify_file(self.fixture.root, alias, self.fixture.bundle)

    def test_missing_matrix_row_fails(self) -> None:
        text = self.fixture.transcript().replace(
            "rep2  compat         p50 = 1.0  p90 = 2.0  p99 = 3.0  p99.9 = 4.0\n",
            "",
            1,
        )
        with self.assertRaisesRegex(TranscriptError, "row order/set"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_malformed_reserved_prefix_fails(self) -> None:
        text = self.fixture.transcript().replace(
            f"commit: {self.fixture.commit}\n",
            f"commit: {self.fixture.commit}\ncommit: malformed\n",
        )
        with self.assertRaisesRegex(TranscriptError, "malformed reserved-prefix"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_duplicate_valid_commit_fails(self) -> None:
        line = f"commit: {self.fixture.commit}\n"
        text = self.fixture.transcript().replace(line, line + line)
        with self.assertRaisesRegex(TranscriptError, "exactly one commit"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_non_monotonic_percentiles_fail(self) -> None:
        text = self.fixture.transcript().replace(
            "p50 = 1.0  p90 = 2.0  p99 = 3.0  p99.9 = 4.0",
            "p50 = 5.0  p90 = 2.0  p99 = 3.0  p99.9 = 4.0",
            1,
        )
        with self.assertRaisesRegex(TranscriptError, "not monotonic"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_zero_percentile_fails_reserved_schema(self) -> None:
        text = self.fixture.transcript().replace("p50 = 1.0", "p50 = 0.0", 1)
        with self.assertRaisesRegex(TranscriptError, "finite and positive"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_nonzero_secret_mlkem_probe_fails(self) -> None:
        text = self.fixture.transcript().replace(
            "ml-kem-probe:      ERROR SUMMARY: 0 errors",
            "ml-kem-probe:      ERROR SUMMARY: 1 errors",
        )
        with self.assertRaisesRegex(TranscriptError, "ml-kem-probe reported"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_zero_synthetic_leaky_control_fails(self) -> None:
        text = self.fixture.transcript().replace(
            "leaky-control:     ERROR SUMMARY: 9 errors",
            "leaky-control:     ERROR SUMMARY: 0 errors",
        )
        with self.assertRaisesRegex(TranscriptError, "planted-leak discriminator"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_synthetic_discriminator_count_mismatch_fails(self) -> None:
        text = self.fixture.transcript().replace(
            "ML-KEM probe=0 vs planted secret branch=9",
            "ML-KEM probe=0 vs planted secret branch=8",
        )
        with self.assertRaisesRegex(TranscriptError, "count does not match"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_zero_public_mlkem_positive_control_fails(self) -> None:
        text = self.fixture.transcript().replace(
            "ml-kem-ek:         ERROR SUMMARY: 17 errors",
            "ml-kem-ek:         ERROR SUMMARY: 0 errors",
        )
        with self.assertRaisesRegex(TranscriptError, "positive control reported no"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_netem_loss_is_rejected(self) -> None:
        record = json.loads(self.fixture.artifact_data["qdisc_10ms"])
        record[0]["options"]["loss"] = 1
        data = json.dumps(record, separators=(",", ":")).encode()
        text = self.fixture.rewrite_bound_artifact("qdisc_10ms", data)
        with self.assertRaisesRegex(TranscriptError, "forbidden non-zero loss"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_wrong_netem_delay_is_rejected(self) -> None:
        record = json.loads(self.fixture.artifact_data["qdisc_25ms"])
        record[0]["options"]["delay"] = 24000
        data = json.dumps(record, separators=(",", ":")).encode()
        text = self.fixture.rewrite_bound_artifact("qdisc_25ms", data)
        with self.assertRaisesRegex(TranscriptError, "not exactly 25 ms"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_qdisc_after_must_byte_match_baseline(self) -> None:
        text = self.fixture.rewrite_bound_artifact(
            "qdisc_after", b'[{"kind":"noqueue","root":true}] \n'
        )
        with self.assertRaisesRegex(TranscriptError, "restored qdisc bytes differ"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_nonfinite_or_unknown_qdisc_json_is_rejected(self) -> None:
        with self.assertRaisesRegex(TranscriptError, "non-finite JSON number"):
            validate_netem_bytes(
                b'[{"kind":"noqueue","root":true,"refcnt":NaN}]', 0
            )
        with self.assertRaisesRegex(TranscriptError, "unknown fields"):
            validate_netem_bytes(
                b'[{"kind":"noqueue","root":true,"unexpected":1}]', 0
            )

    def test_sparse_archive_member_is_rejected_before_expansion(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo("sparse.bin")
            member.size = 1
            member.pax_headers = {"GNU.sparse.map": "0,1"}
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(TranscriptError, "sparse member"):
            _archive_files(output.getvalue())

    def test_fifo_transcript_is_rejected_without_blocking(self) -> None:
        fifo = pathlib.Path(self.temp.name) / "transcript.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(TranscriptError, "not a regular file"):
            verify_file(self.fixture.root, fifo, self.fixture.bundle)

    def test_freeze_binary_rejects_unsafe_source_metadata(self) -> None:
        owner = os.getuid()
        self.assertGreater(owner, 0)
        base = pathlib.Path(self.temp.name)

        regular = base / "runner-binary"
        regular.write_bytes(b"binary")
        regular.chmod(0o700)
        digest = _freeze_binary(regular, base / "frozen-binary", owner)
        self.assertEqual(digest, hashlib.sha256(b"binary").hexdigest())
        with self.assertRaisesRegex(TranscriptError, "metadata is unsafe"):
            _freeze_binary(regular, base / "wrong-owner-output", owner + 1)

        fifo = base / "binary.fifo"
        os.mkfifo(fifo, 0o700)
        with self.assertRaisesRegex(TranscriptError, "metadata is unsafe"):
            _freeze_binary(fifo, base / "fifo-output", owner)

        hardlink = base / "runner-binary-link"
        os.link(regular, hardlink)
        with self.assertRaisesRegex(TranscriptError, "metadata is unsafe"):
            _freeze_binary(regular, base / "hardlink-output", owner)

        oversized = base / "oversized-binary"
        with oversized.open("wb") as stream:
            stream.truncate(MAX_MEASURED_BINARY_BYTES + 1)
        oversized.chmod(0o700)
        with self.assertRaisesRegex(TranscriptError, "metadata is unsafe"):
            _freeze_binary(oversized, base / "oversized-output", owner)

    def test_tuning_after_must_restore_before_value(self) -> None:
        data = self.fixture.artifact_data["tuning_after"].replace(
            b"sysctl\tnet.ipv4.tcp_tw_reuse\t2\t1\t2\n",
            b"sysctl\tnet.ipv4.tcp_tw_reuse\t2\t1\t1\n",
        )
        text = self.fixture.rewrite_bound_artifact("tuning_after", data)
        with self.assertRaisesRegex(TranscriptError, "host tuning was not restored"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_build_warning_is_rejected(self) -> None:
        data = b"warning: compiler diagnostic\n"
        text = self.fixture.rewrite_bound_artifact("ct_build_log", data)
        with self.assertRaisesRegex(TranscriptError, "contains a warning or error"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_noncanonical_manifest_is_rejected(self) -> None:
        pretty = (json.dumps(json.loads(self.fixture.manifest_data), indent=2) + "\n").encode()
        text = self.fixture.transcript_for_manifest(pretty)
        with self.assertRaisesRegex(TranscriptError, "not canonical JSON"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_duplicate_manifest_key_is_rejected(self) -> None:
        duplicate = self.fixture.manifest_data.replace(
            b'{"artifacts":', b'{"schema_version":1,"artifacts":', 1
        )
        text = self.fixture.transcript_for_manifest(duplicate)
        with self.assertRaisesRegex(TranscriptError, "duplicate JSON key"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_boolean_schema_version_is_rejected(self) -> None:
        manifest = json.loads(self.fixture.manifest_data)
        manifest["schema_version"] = True
        data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        text = self.fixture.transcript_for_manifest(data)
        with self.assertRaisesRegex(TranscriptError, "schema_version must be an integer"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_schema_version_one_is_rejected(self) -> None:
        manifest = json.loads(self.fixture.manifest_data)
        manifest["schema_version"] = 1
        data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        text = self.fixture.transcript_for_manifest(data)
        with self.assertRaisesRegex(TranscriptError, "schema_version is invalid"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_previous_schema_version_is_rejected(self) -> None:
        manifest = json.loads(self.fixture.manifest_data)
        manifest["schema_version"] = 2
        data = (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        text = self.fixture.transcript_for_manifest(data)
        with self.assertRaisesRegex(TranscriptError, "schema_version is invalid"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_float_artifact_size_is_rejected(self) -> None:
        manifest = json.loads(self.fixture.manifest_data)
        manifest["artifacts"]["summary"]["size"] = float(
            manifest["artifacts"]["summary"]["size"]
        )
        data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        text = self.fixture.transcript_for_manifest(data)
        with self.assertRaisesRegex(TranscriptError, "size must be a non-negative integer"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_stale_capture_fails_when_freshness_is_required(self) -> None:
        now = dt.datetime(2026, 7, 20, tzinfo=dt.timezone.utc)
        with self.assertRaisesRegex(TranscriptError, "capture is stale"):
            verify_text(
                self.fixture.root,
                self.fixture.transcript(),
                self.fixture.bundle,
                max_age_seconds=60,
                now=now,
            )

    def test_symlink_bundle_member_fails(self) -> None:
        target = self.fixture.bundle / BUNDLE_ARTIFACTS["summary"]
        target.unlink()
        target.symlink_to("measurements.tsv")
        with self.assertRaisesRegex(TranscriptError, "flat and contain only regular files"):
            verify_text(self.fixture.root, self.fixture.transcript(), self.fixture.bundle)

    def test_cpu_metadata_mismatch_is_rejected(self) -> None:
        text = self.fixture.transcript().replace(
            f"cpu  : {CPU_NAME}", "cpu  : forged cpu", 1
        )
        with self.assertRaisesRegex(TranscriptError, "capture metadata .* differs"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_pin_metadata_mismatch_is_rejected(self) -> None:
        text = self.fixture.transcript().replace(
            f"pin  : cores {PIN}", "pin  : cores 6-7", 1
        )
        with self.assertRaisesRegex(TranscriptError, "capture metadata .* differs"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_rustc_metadata_mismatch_is_rejected(self) -> None:
        text = self.fixture.transcript().replace(
            RUSTC_VERSION, "rustc 1.97.0 (forged)", 1
        )
        with self.assertRaisesRegex(TranscriptError, "capture metadata .* differs"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_cargo_seed_metadata_mismatch_is_rejected(self) -> None:
        metadata = json.loads(self.fixture.artifact_data["capture_metadata"])
        metadata["cargo_seed"]["package_count"] += 1
        data = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode()
        text = self.fixture.rewrite_bound_artifact("capture_metadata", data)
        with self.assertRaisesRegex(TranscriptError, "capture metadata .* differs"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_cargo_seed_checksum_must_match_lock(self) -> None:
        data = self.fixture.artifact_data["cargo_seed_manifest"].replace(
            ALPHA_CHECKSUM.encode(), ("c" * 64).encode(), 1
        )
        text = self.fixture.rewrite_bound_artifact("cargo_seed_manifest", data)
        with self.assertRaisesRegex(TranscriptError, "checksum differs from Cargo.lock"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_cargo_seed_extra_crate_is_rejected(self) -> None:
        data = self.fixture.artifact_data["cargo_seed_manifest"] + (
            "registry/cache/index.crates.io-test/gamma-3.0.0.crate\t303\t"
            + "c" * 64
            + "\n"
        ).encode()
        text = self.fixture.rewrite_bound_artifact("cargo_seed_manifest", data)
        with self.assertRaisesRegex(TranscriptError, "crate closure differs.*extra"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_cargo_seed_missing_crate_is_rejected(self) -> None:
        beta_row = (
            "registry/cache/index.crates.io-test/beta-2.0.0.crate\t202\t"
            + BETA_CHECKSUM
            + "\n"
        ).encode()
        data = self.fixture.artifact_data["cargo_seed_manifest"].replace(beta_row, b"")
        text = self.fixture.rewrite_bound_artifact("cargo_seed_manifest", data)
        with self.assertRaisesRegex(TranscriptError, "crate closure differs.*missing"):
            verify_text(self.fixture.root, text, self.fixture.bundle)

    def test_shell_staging_and_manifest_finalizer_match_verifier_schema(self) -> None:
        shell = (
            pathlib.Path(__file__).resolve().parents[1] / "camera-ready-bare-metal.sh"
        ).read_text(encoding="utf-8")
        destinations = re.findall(
            r"^\s*stage_bundle_member\s+\S+\s+([A-Za-z0-9_.-]+)\s+\|\|",
            shell,
            flags=re.MULTILINE,
        )
        self.assertCountEqual(destinations, BUNDLE_ARTIFACTS.values())
        self.assertEqual(len(destinations), len(set(destinations)))
        self.assertIsNone(re.search(r"(?m)^\s*paths\s*=\s*\{", shell))
        self.assertNotIn("json.dumps(manifest", shell)
        self.assertEqual(len(re.findall(r"\bfinalize --bundle\b", shell)), 1)


if __name__ == "__main__":
    unittest.main()
