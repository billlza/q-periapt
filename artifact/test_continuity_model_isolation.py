import json
import pathlib
import re
import subprocess
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODEL_NAME = "q-periapt-continuity-model"
MODEL_ROOT = ROOT / "models" / MODEL_NAME
MODEL_MANIFEST = MODEL_ROOT / "Cargo.toml"


def cargo_metadata() -> dict[str, object]:
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--no-deps",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(completed.stdout)
    if not isinstance(metadata, dict):
        raise TypeError("cargo metadata did not return a JSON object")
    return metadata


def dependency_tables(manifest: dict[str, object]) -> list[dict[str, object]]:
    tables: list[dict[str, object]] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = manifest.get(key)
        if isinstance(value, dict):
            tables.append(value)

    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        value = workspace.get("dependencies")
        if isinstance(value, dict):
            tables.append(value)

    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = target.get(key)
                if isinstance(value, dict):
                    tables.append(value)
    return tables


def repository_manifests() -> list[pathlib.Path]:
    manifests: list[pathlib.Path] = []
    for path in ROOT.rglob("Cargo.toml"):
        relative_parts = path.relative_to(ROOT).parts
        if "target" in relative_parts or ".git" in relative_parts:
            continue
        manifests.append(path)
    return sorted(manifests)


def dependency_package_name(alias: str, specification: object) -> str:
    if isinstance(specification, dict):
        package = specification.get("package")
        if isinstance(package, str):
            return package
    return alias


def rust_code_without_comments_or_literals(source: str) -> str:
    """Mask comments and literals while preserving line numbers for diagnostics."""

    masked: list[str] = []
    cursor = 0
    length = len(source)

    def mask(character: str) -> str:
        return "\n" if character == "\n" else " "

    while cursor < length:
        if source.startswith("//", cursor):
            end = source.find("\n", cursor + 2)
            if end == -1:
                end = length
            masked.extend(mask(character) for character in source[cursor:end])
            cursor = end
            continue

        if source.startswith("/*", cursor):
            depth = 1
            end = cursor + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ValueError("unterminated Rust block comment")
            masked.extend(mask(character) for character in source[cursor:end])
            cursor = end
            continue

        raw = re.match(r'(?:br|cr|r)(?P<hashes>#{0,255})"', source[cursor:])
        if raw is not None:
            terminator = '"' + raw.group("hashes")
            end = source.find(terminator, cursor + raw.end())
            if end == -1:
                raise ValueError("unterminated Rust raw string literal")
            end += len(terminator)
            masked.extend(mask(character) for character in source[cursor:end])
            cursor = end
            continue

        string_prefix_length = 0
        if source[cursor] == '"':
            string_prefix_length = 1
        elif source.startswith(('b"', 'c"'), cursor):
            string_prefix_length = 2
        if string_prefix_length:
            end = cursor + string_prefix_length
            escaped = False
            while end < length:
                character = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    break
            else:
                raise ValueError("unterminated Rust string literal")
            masked.extend(mask(character) for character in source[cursor:end])
            cursor = end
            continue

        masked.append(source[cursor])
        cursor += 1

    return "".join(masked)


class ContinuityModelIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.metadata = cargo_metadata()

    def test_locked_metadata_marks_model_unpublishable_and_dependency_free(self) -> None:
        packages = self.metadata.get("packages")
        self.assertIsInstance(packages, list)
        matching = [package for package in packages if package.get("name") == MODEL_NAME]
        self.assertEqual(len(matching), 1)
        model = matching[0]
        self.assertEqual(model.get("publish"), [])
        self.assertEqual(model.get("dependencies"), [])

        workspace_members = self.metadata.get("workspace_members")
        self.assertIsInstance(workspace_members, list)
        self.assertIn(model.get("id"), workspace_members)

    def test_product_workspace_has_no_reverse_dependency_on_model(self) -> None:
        packages = self.metadata.get("packages")
        workspace_members = self.metadata.get("workspace_members")
        self.assertIsInstance(packages, list)
        self.assertIsInstance(workspace_members, list)
        workspace_member_ids = set(workspace_members)

        reverse_dependencies: list[str] = []
        for package in packages:
            if package.get("id") not in workspace_member_ids or package.get("name") == MODEL_NAME:
                continue
            for dependency in package.get("dependencies", []):
                if dependency.get("name") == MODEL_NAME:
                    reverse_dependencies.append(str(package.get("name")))
        self.assertEqual(reverse_dependencies, [])

    def test_every_repository_manifest_rejects_direct_and_aliased_model_dependencies(self) -> None:
        manifests = repository_manifests()
        self.assertIn(MODEL_MANIFEST, manifests)
        offenders: list[str] = []
        for path in manifests:
            manifest = tomllib.loads(path.read_text(encoding="utf-8"))
            for table in dependency_tables(manifest):
                for alias, specification in table.items():
                    if dependency_package_name(alias, specification) == MODEL_NAME:
                        relative = path.relative_to(ROOT).as_posix()
                        offenders.append(f"{relative}: {alias}")
        self.assertEqual(offenders, [])

    def test_library_source_has_no_arbitrary_payload_or_logging_surface(self) -> None:
        forbidden_patterns = {
            "owned dynamic payload type": re.compile(r"\b(?:String|Vec|Box|Cow|ToString)\b"),
            "borrowed string payload type": re.compile(
                r"&\s*(?:'[A-Za-z_][A-Za-z0-9_]*\s*)?(?:mut\s+)?str\b"
            ),
            "format or logging macro": re.compile(
                r"\b(?:format|format_args|print|println|eprint|eprintln|dbg|debug|info|warn|error|trace|write|writeln)\s*!"
            ),
            "logging facade": re.compile(r"\b(?:log|tracing)\s*::"),
        }
        source_files = sorted((MODEL_ROOT / "src").rglob("*.rs"))
        self.assertGreater(len(source_files), 0)
        offenders: list[str] = []
        for path in source_files:
            source = path.read_text(encoding="utf-8")
            code = rust_code_without_comments_or_literals(source)
            for description, pattern in forbidden_patterns.items():
                for match in pattern.finditer(code):
                    line = code.count("\n", 0, match.start()) + 1
                    relative = path.relative_to(ROOT).as_posix()
                    offenders.append(f"{relative}:{line}: {description}: {match.group(0)!r}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
