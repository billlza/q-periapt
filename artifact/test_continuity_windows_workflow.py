"""Guard Windows same-run package provenance and actual input trigger coverage.

These tests inspect workflow routing and source inputs. They do not manufacture
SDK archives or replace installed Windows execution.
"""
import ast
from pathlib import Path
import re
import subprocess
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ".github/workflows/continuity-windows-package.yml"


def job(text, name):
    match = re.search(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
                      text.split("\njobs:\n", 1)[1])
    if match is None:
        raise ValueError(f"missing job: {name}")
    return match[1]


def steps(block, action):
    return [part for part in re.split(r"(?m)^      - ", block)[1:]
            if re.search(r"(?m)^(?:uses: |        uses: )actions/" + re.escape(action) + "@", part)]


def option(block, name):
    values = re.findall(r"(?m)^          " + re.escape(name) + r": ([^\n]+)$", block)
    if len(values) != 1:
        raise ValueError(f"expected one {name}")
    return values[0].strip().strip("'\"")


def validate_provenance(text):
    producer, prepare = job(text, "sdk-package"), job(text, "prepare")
    if "    needs: sdk-package\n" not in prepare:
        raise ValueError("prepare must depend on successful same-run SDK production")
    for block in (producer, prepare):
        if re.search(r"(?m)^\s+continue-on-error:|^    if:", block):
            raise ValueError("producer/prepare failure cannot be bypassed")
        checkouts = steps(block, "checkout")
        if len(checkouts) != 1 or re.search(r"(?m)^          (?:ref|repository):", checkouts[0]):
            raise ValueError("producer and prepare must use the workflow checkout")
    command = "sh artifact/rust-publish-contract.sh --profile sdk-020 --output target/sdk-rust-package"
    if producer.count(command) != 1:
        raise ValueError("the current SDK cohort must actually be produced")
    uploads = [part for part in steps(producer, "upload-artifact")
               if option(part, "name") == "windows-sdk-package"]
    downloads = steps(prepare, "download-artifact")
    if len(uploads) != 1 or len(downloads) != 1:
        raise ValueError("expected one SDK upload and one same-run download")
    if option(downloads[0], "name") != option(uploads[0], "name"):
        raise ValueError("SDK artifact identity differs")
    if re.search(r"(?m)^          (?:run-id|repository|github-token):", downloads[0]):
        raise ValueError("cross-run SDK download is forbidden")
    if option(downloads[0], "path") != "target/windows-sdk-input":
        raise ValueError("SDK download root differs")
    if any(line not in uploads[0] for line in (
            "            target/sdk-rust-package/crates/*.crate\n",
            "            target/sdk-rust-package/*.json\n")):
        raise ValueError("SDK report and exact archive closure must be retained")
    required = (
        "          EXPECTED_SDK_COMMIT: ${{ github.sha }}\n",
        "            --report target/windows-sdk-input/RUST_SDK_PACKAGE.json",
        '            --sdk-commit "$EXPECTED_SDK_COMMIT"',
    )
    if any(value not in prepare for value in required):
        raise ValueError("SDK admission must bind the same workflow commit and report")


def push_paths(text):
    header = text.split("\npermissions:\n", 1)[0]
    match = re.search(r"(?m)^    paths:\n((?:      - [^\n]+\n)+)", header)
    if match is None or "    paths-ignore:" in header:
        raise ValueError("expected the explicit push input boundary")
    return [line.removeprefix("      - ") for line in match[1].splitlines()]


def path_matches(pattern, path):
    # The maintained workflow uses only literal paths, * and **. Unlike
    # fnmatch, GitHub's single * must not cross a directory separator.
    if any(character in pattern for character in "!+?[]{}"):
        raise ValueError("unsupported workflow path pattern")
    expression, index = "", 0
    while index < len(pattern):
        if pattern[index:index + 3] == "**/":
            expression += "(?:.*/)?"
            index += 3
        elif pattern[index:index + 2] == "**":
            expression += ".*"
            index += 2
        elif pattern[index] == "*":
            expression += "[^/]*"
            index += 1
        else:
            expression += re.escape(pattern[index])
            index += 1
    return re.fullmatch(expression, path) is not None


def triggered(patterns, path):
    return any(path_matches(pattern, path) for pattern in patterns)


def literal(path, name):
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError(f"missing input declaration: {name}")


def required_inputs(root):
    tracked = set(subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True,
        timeout=10).stdout.decode("utf-8").rstrip("\0").split("\0"))
    roots = list(literal(root / "artifact/c_package_manifest.py", "RUST_WORKSPACE_INPUTS"))
    roots += [literal(root / "artifact/rust_sdk_profile.py", "FIXTURE"),
              "research/continuity-identity-candidate", "bindings/c/ContinuityPackageConsumer",
              ".cargo", "LICENSES"]
    selected = {path for path in tracked if any(
        path == prefix or path.startswith(prefix + "/") for prefix in roots)}
    selected.update({"Cargo.toml", "Cargo.lock", "README.md", "LICENSE",
                     "fuzz/Cargo.toml", "fuzz/Cargo.lock", WORKFLOW})
    selected.update({path for path in (".gitattributes", ".gitignore") if path in tracked})
    policies = literal(root / "artifact/rust_sdk_profile.py", "POLICIES")
    selected.update("bindings/" + name for name in policies)
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    for member in workspace["workspace"]["members"]:
        selected.update(path.relative_to(root).as_posix()
                        for directory in root.glob(member)
                        if (path := directory / "Cargo.toml").is_file())
    pending = {
        "artifact/rust_sdk_profile.py", "artifact/continuity_windows_prepare.py",
        "artifact/continuity_windows_consume.py", "artifact/continuity_windows_network_review.py",
        "artifact/test_continuity_fetch.py", "artifact/python_bootstrap.py",
    }
    pending.update(path for path in tracked
                   if path.startswith("artifact/test_continuity_windows_") and path.endswith(".py"))
    selected.update({"artifact/rust-publish-contract.sh", "artifact/python-run.sh",
                     "artifact/python-env.sh"})
    # Follow real local imports, including imports inside functions, so a new
    # reader dependency cannot silently escape the triggering input boundary.
    visited = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        selected.add(path)
        for node in ast.walk(ast.parse((root / path).read_text(encoding="utf-8"))):
            modules = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                       else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for module in modules:
                dependency = "artifact/" + module.split(".")[0] + ".py"
                if dependency in tracked and dependency not in visited:
                    pending.add(dependency)
    return selected


class WindowsWorkflowInputsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / WORKFLOW).read_text(encoding="utf-8")
        cls.paths = push_paths(cls.text)
        cls.inputs = required_inputs(ROOT)

    def test_pull_requests_to_the_integration_branch_use_the_same_inputs(self):
        header = self.text.split("\npermissions:\n", 1)[0]
        push, pr = header.split("\n  pull_request:\n", 1)
        self.assertEqual(push_paths(push + "\n"), push_paths(pr))
        self.assertIn("    branches: [lza/windows-private-store]\n", pr)
        self.assertNotIn("pull_request_target:", header)

    def test_same_run_producer_and_commit_admission(self):
        validate_provenance(self.text)

    def test_cross_run_missing_dependency_or_wrong_commit_refuse(self):
        for before, after in (
            ("    needs: sdk-package\n", ""),
            ("          name: windows-sdk-package\n          path: target/windows-sdk-input",
             "          name: windows-sdk-package\n          run-id: 39078307221\n          path: target/windows-sdk-input"),
            ("          name: windows-sdk-package\n          path: target/windows-sdk-input",
             "          name: unrelated-sdk\n          path: target/windows-sdk-input"),
            ("EXPECTED_SDK_COMMIT: ${{ github.sha }}", "EXPECTED_SDK_COMMIT: " + "a" * 40),
            ('--sdk-commit "$EXPECTED_SDK_COMMIT"', "--sdk-commit " + "a" * 40),
            ("--report target/windows-sdk-input/RUST_SDK_PACKAGE.json",
             "--report target/windows-sdk-input/sdk-rust-package/RUST_SDK_PACKAGE.json"),
            ("--profile sdk-020 --output target/sdk-rust-package", "--profile legacy"),
            ("    needs: sdk-package\n", "    needs: sdk-package\n    if: always()\n"),
            ("  sdk-package:\n", "  sdk-package:\n    continue-on-error: true\n"),
            ("          persist-credentials: false\n",
             "          persist-credentials: false\n          ref: historical\n"),
        ):
            with self.subTest(before=before):
                changed = self.text.replace(before, after, 1)
                self.assertNotEqual(changed, self.text)
                with self.assertRaises(ValueError):
                    validate_provenance(changed)

    def test_every_actual_producer_consumer_and_reader_input_triggers(self):
        self.assertGreater(len(self.inputs), 100)
        missing = sorted(path for path in self.inputs if not triggered(self.paths, path))
        self.assertEqual(missing, [], "actual Windows qualification inputs would not trigger CI")

    def test_glob_semantics_distinguish_files_from_nested_inputs(self):
        for pattern, path, expected in (
            ("LICENSE*", "LICENSE", True),
            ("LICENSE*", "LICENSES/MIT.txt", False),
            ("LICENSES/**", "LICENSES/MIT.txt", True),
            ("artifact/*.py", "artifact/nested/reader.py", False),
            ("artifact/**", "artifact/nested/reader.py", True),
            ("artifact/**/reader.py", "artifact/reader.py", True),
            ("rust-toolchain*", "rust-toolchain.example", True),
        ):
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(path_matches(pattern, path), expected)
        for path in ("rust-toolchain.example", "artifact/new-reader/verify.py"):
            self.assertTrue(triggered(self.paths, path))
        for path in ("docs/design-only.md", "research/unrelated-experiment/results.json",
                     "bindings/android/unrelated/README.md"):
            self.assertFalse(triggered(self.paths, path))


if __name__ == "__main__":
    unittest.main()
