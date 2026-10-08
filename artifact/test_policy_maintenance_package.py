"""Reject mixed archive consumers and changes to a pinned maintenance package."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import policy_maintenance_package as maintenance
import rust_sdk_profile as sdk


class MaintenancePackageTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()

    def metadata(self):
        return {"packages": [{"name": name, "id": name, "source": None, "version": sdk.VERSION,
            "manifest_path": str(self.root / "packages" / f"{name}-{sdk.VERSION}" / "Cargo.toml")}
            for name in sorted(maintenance.RESOLVED_NAMES)],
            "resolve": {"nodes": [{"id": maintenance.NAME, "features": ["policy-store-migration"]}]}}

    def lock(self):
        return ('version = 4\n' + ''.join(
            f'[[package]]\nname="{name}"\nversion="{version}"\n'
            'source="registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum="{letter * 64}"\n'
            for name, version, letter in [('redb', '2.6.4', 'a'), ('redb', '4.3.0', 'b'),
                                         ('twox-hash', '2.1.4', 'c')])).encode()

    def test_resolution_rejects_wrong_paths_features_and_external_identity(self):
        original = self.metadata()
        lock = self.lock()
        maintenance.validate_resolution(original, self.root, lock, lock)
        for change in ("path", "extra", "version", "source", "feature", "checksum", "missing"):
            changed = copy.deepcopy(original)
            selected_lock = lock
            if change == "path": changed["packages"][0]["manifest_path"] = "/checkout/Cargo.toml"
            if change == "extra": changed["packages"].append(dict(changed["packages"][0], name="unexpected"))
            if change == "version": changed["packages"][0]["version"] = "0.1.5"
            if change == "source": changed["packages"][0]["source"] = "registry+https://github.com/rust-lang/crates.io-index"
            if change == "feature": changed["resolve"]["nodes"][0]["features"] = []
            if change == "checksum": selected_lock = lock.replace(b'a' * 64, b'd' * 64)
            if change == "missing":
                entries = lock.split(b'[[package]]')
                selected_lock = entries[0] + b'[[package]]' + b'[[package]]'.join(entries[2:])
            with self.subTest(change=change), self.assertRaises(ValueError):
                maintenance.validate_resolution(changed, self.root, selected_lock, lock)

    def test_pinned_payload_rejects_missing_extra_tampered_mode_and_symlink(self):
        for name in (*maintenance.PAYLOAD_SOURCES, "bin/qperiapt", str(maintenance.licenses.INVENTORY_RELATIVE)):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture")
            path.chmod(0o755 if name == "bin/qperiapt" else 0o644)
        manifest = {key: None for key in maintenance.MANIFEST_KEYS}
        manifest.update(kind=maintenance.KIND, schema_version=1, version=sdk.VERSION,
                        target="aarch64-apple-darwin", files=maintenance.payload(self.root))
        data = json.dumps(manifest).encode()
        (self.root / "MANIFEST.json").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        # License inventory parsing has its own strict fixture tests. Here only
        # stub that sub-boundary; archive and payload bytes remain real files.
        with patch.object(maintenance.licenses, "verify", return_value={"packages": []}):
            maintenance.verify_payload(self.root, "aarch64-apple-darwin", digest)
            with self.assertRaisesRegex(ValueError, "digest differs"):
                maintenance.verify_payload(self.root, "aarch64-apple-darwin", "f" * 64)
            with self.assertRaisesRegex(ValueError, "identity differs"):
                maintenance.verify_payload(self.root, "x86_64-unknown-linux-gnu", digest)
            binary = self.root / "bin/qperiapt"
            for mutation in ("tampered", "missing", "extra", "mode", "symlink"):
                with self.subTest(mutation=mutation):
                    if mutation == "tampered": binary.write_bytes(b"changed")
                    if mutation == "missing": binary.unlink()
                    if mutation == "extra": (self.root / "unexpected").write_bytes(b"extra")
                    if mutation == "mode": binary.chmod(0o644)
                    if mutation == "symlink":
                        binary.unlink()
                        binary.symlink_to(self.root / "README.md")
                    with self.assertRaises(ValueError):
                        maintenance.verify_payload(self.root, "aarch64-apple-darwin", digest)
                    if binary.exists() or binary.is_symlink(): binary.unlink()
                    binary.write_bytes(b"fixture")
                    binary.chmod(0o755)
                    if (self.root / "unexpected").exists(): (self.root / "unexpected").unlink()


if __name__ == "__main__":
    unittest.main()
