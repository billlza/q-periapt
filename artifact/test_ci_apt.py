"""Exercise the installer configuration and real APT's signed mirror boundary."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest


SCRIPT = Path(__file__).with_name("ci_apt.sh")
ARCHIVE_KEY = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"


def configure(root: Path, suite: str = "noble", architecture: str = "amd64"):
    return subprocess.run(
        ["bash", "-c", 'source "$1"; write_sources "$2" ubuntu "$3" "$4"',
         "configure", str(SCRIPT), str(root), suite, architecture],
        capture_output=True, text=True, timeout=10, check=False,
    )


class AptSourceConfigurationTests(unittest.TestCase):
    def test_all_supported_targets_keep_archive_trust_and_architecture_selection(self):
        for suite, arch in (("jammy", "amd64"), ("noble", "amd64"),
                            ("resolute", "amd64"), ("resolute", "amd64v3"),
                            ("noble", "arm64")):
            with self.subTest(suite=suite, arch=arch), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                result = configure(root, suite, arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                mirrors = (root / "mirrors.list").read_text().splitlines()
                self.assertEqual(len(mirrors), 2)
                self.assertTrue(mirrors[0].endswith("\tpriority:1"))
                self.assertTrue(mirrors[1].endswith("\tpriority:2"))
                self.assertTrue(all(line.startswith("https://") for line in mirrors))
                primary = ("https://ports.ubuntu.com/ubuntu-ports" if arch == "arm64"
                           else "https://archive.ubuntu.com/ubuntu")
                self.assertEqual(mirrors[0], primary + "\tpriority:1")
                sources = (root / "sources.list").read_text().splitlines()
                self.assertEqual(sources, [
                    f"deb [signed-by={ARCHIVE_KEY}] mirror+file:{root}/mirrors.list "
                    f"{pocket} main restricted universe multiverse"
                    for pocket in (suite, suite + "-updates", suite + "-security", suite + "-backports")
                ])

    def test_unsupported_target_fails_before_emitting_sources(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result = configure(root, "noble", "unsupported")
            self.assertEqual(result.returncode, 2)
            self.assertIn("unsupported Ubuntu suite/architecture", result.stderr)
            self.assertEqual(list(root.iterdir()), [])


@unittest.skipUnless(sys.platform == "linux", "real APT acquisition requires Linux")
class AptMirrorAcquisitionTests(unittest.TestCase):
    def setUp(self):
        for tool in ("apt-get", "gpg", "dpkg-deb"):
            self.assertIsNotNone(shutil.which(tool), f"required Linux test tool: {tool}")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.gnupg = self.root / "gnupg"
        self.gnupg.mkdir(mode=0o700)
        self.gpg("--quick-generate-key", "APT fixture <fixture@example.invalid>", "ed25519", "sign", "0")
        self.keyring = self.root / "fixture.gpg"
        self.keyring.write_bytes(self.gpg("--export").stdout)
        package = self.root / "package"
        (package / "DEBIAN").mkdir(parents=True)
        (package / "DEBIAN/control").write_text(
            "Package: qperiapt-apt-fixture\nVersion: 1.0\nArchitecture: all\n"
            "Maintainer: Test <fixture@example.invalid>\nDescription: isolated acquisition fixture\n")
        (package / "usr/share/qperiapt-apt-fixture").mkdir(parents=True)
        (package / "usr/share/qperiapt-apt-fixture/probe").write_text("authenticated fixture\n")
        self.deb = self.repository / "pool/probe.deb"
        self.deb.parent.mkdir()
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(package), str(self.deb)],
                       check=True, capture_output=True, timeout=15)
        self.deb_digest = hashlib.sha256(self.deb.read_bytes()).hexdigest()
        self.write_release()
        self.primary_fails = True
        self.secondary_fails = False
        self.requests = []
        owner = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(owner.repository), **kwargs)

            def do_GET(self):
                owner.requests.append(self.path)
                prefix = self.path.split("/", 2)[1]
                if ((prefix == "primary" and owner.primary_fails)
                        or (prefix == "secondary" and owner.secondary_fails)):
                    self.send_error(503, "controlled mirror outage")
                    return
                if prefix not in ("primary", "secondary"):
                    self.send_error(404)
                    return
                self.path = "/" + self.path.split("/", 2)[2]
                super().do_GET()

            def log_message(self, _format, *args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join, 5)
        self.addCleanup(server.shutdown)
        self.config = self.root / "apt"
        self.config.mkdir()
        result = configure(self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Replace only the external endpoints and signing key in the generated
        # production configuration. No APT process or verification is mocked.
        mirror_file = self.config / "mirrors.list"
        lines = mirror_file.read_text().splitlines()
        mirror_file.write_text("".join(
            f"http://127.0.0.1:{server.server_port}/{prefix}\t{line.split(chr(9), 1)[1]}\n"
            for prefix, line in zip(("primary", "secondary"), lines, strict=True)))
        sources = self.config / "sources.list"
        sources.write_text(sources.read_text().replace(ARCHIVE_KEY, str(self.keyring)))
        (self.config / "status").touch()
        for name in ("sourceparts", "lists/partial", "cache/archives/partial", "trustedparts"):
            (self.config / name).mkdir(parents=True)

    def gpg(self, *arguments):
        return subprocess.run(
            ["gpg", "--batch", "--yes", "--no-options", "--homedir", str(self.gnupg),
             "--pinentry-mode", "loopback", "--passphrase", "", *arguments],
            capture_output=True, timeout=15, check=True,
        )

    def write_release(self, *, expired=False):
        data = ("Package: qperiapt-apt-fixture\nVersion: 1.0\nArchitecture: all\n"
                "Maintainer: Test <fixture@example.invalid>\nDescription: acquisition fixture\n"
                f"Filename: pool/probe.deb\nSize: {self.deb.stat().st_size}\n"
                f"SHA256: {self.deb_digest}\n\n").encode()
        now = datetime.now(timezone.utc)
        for suite in ("noble", "noble-updates", "noble-security", "noble-backports"):
            directory = self.repository / "dists" / suite
            checksums = []
            for component in ("main", "restricted", "universe", "multiverse"):
                relative = f"{component}/binary-amd64/Packages"
                index = directory / relative
                index.parent.mkdir(parents=True, exist_ok=True)
                content = data if component == "main" else b""
                index.write_bytes(content)
                checksums.append(f" {hashlib.sha256(content).hexdigest()} {len(content)} {relative}\n")
            release = directory / "Release"
            release.write_text(
                f"Origin: QPeriapt fixture\nSuite: {suite}\nCodename: {suite}\n"
                f"Date: {format_datetime(now - timedelta(days=2), usegmt=True)}\n"
                f"Valid-Until: {format_datetime(now + timedelta(days=-1 if expired else 2), usegmt=True)}\n"
                "Architectures: amd64\nComponents: main restricted universe multiverse\nSHA256:\n"
                + "".join(checksums))
            self.gpg("--output", str(directory / "InRelease"), "--clearsign", str(release))

    def apt(self, *arguments):
        options = {
            "Dir::Etc::sourcelist": self.config / "sources.list",
            "Dir::Etc::sourceparts": self.config / "sourceparts",
            "Dir::Etc::trusted": self.keyring,
            "Dir::Etc::trustedparts": self.config / "trustedparts",
            "Dir::State::status": self.config / "status",
            "Dir::State::lists": self.config / "lists",
            "Dir::Cache": self.config / "cache",
            "APT::Architecture": "amd64", "Acquire::Retries": "0",
            "Acquire::http::Timeout": "2", "Acquire::Languages": "none",
            "Acquire::Check-Date": "true", "Acquire::Check-Valid-Until": "true",
            "Acquire::AllowInsecureRepositories": "false",
            "Acquire::AllowDowngradeToInsecureRepositories": "false",
            "APT::Get::AllowUnauthenticated": "false", "APT::Update::Error-Mode": "any",
        }
        return subprocess.run(
            ["apt-get", *(word for k, v in options.items() for word in ("-o", f"{k}={v}")),
             *arguments], env={**os.environ, "LC_ALL": "C"},
            capture_output=True, text=True, timeout=30, check=False,
        )

    def test_unavailable_primary_fetches_verified_package_from_secondary(self):
        updated = self.apt("update")
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        downloaded = self.apt("install", "--download-only", "--yes", "qperiapt-apt-fixture")
        self.assertEqual(downloaded.returncode, 0, downloaded.stdout + downloaded.stderr)
        archives = list((self.config / "cache/archives").glob("*.deb"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(hashlib.sha256(archives[0].read_bytes()).hexdigest(), self.deb_digest)
        self.assertTrue(any(p.startswith("/primary/") for p in self.requests))
        self.assertIn("/secondary/pool/probe.deb", self.requests)
        self.assertEqual((self.config / "status").read_bytes(), b"")

    def test_all_mirrors_unavailable_is_failure(self):
        self.secondary_fails = True
        updated = self.apt("update")
        self.assertNotEqual(updated.returncode, 0)
        self.assertIn("503", updated.stdout + updated.stderr)

    def test_invalid_signature_is_failure(self):
        for signed in self.repository.glob("dists/*/InRelease"):
            signed.write_bytes(signed.read_bytes().replace(b"Origin: QPeriapt", b"Origin: Tampered"))
        updated = self.apt("update")
        self.assertNotEqual(updated.returncode, 0)
        self.assertIn("signature", (updated.stdout + updated.stderr).lower())

    def test_expired_signed_release_is_failure(self):
        self.write_release(expired=True)
        updated = self.apt("update")
        self.assertNotEqual(updated.returncode, 0)
        self.assertIn("expired", (updated.stdout + updated.stderr).lower())

    def test_package_hash_mismatch_is_failure(self):
        updated = self.apt("update")
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        self.deb.write_bytes(b"x" * self.deb.stat().st_size)
        downloaded = self.apt("install", "--download-only", "--yes", "qperiapt-apt-fixture")
        self.assertNotEqual(downloaded.returncode, 0)
        self.assertIn("Hash Sum mismatch", downloaded.stdout + downloaded.stderr)
        self.assertEqual(list((self.config / "cache/archives").glob("*.deb")), [])


if __name__ == "__main__":
    unittest.main()
