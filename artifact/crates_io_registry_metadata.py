#!/usr/bin/env python3
"""Reconstruct the exact registry metadata JSON that ``cargo publish`` transmits
to crates.io for a packaged crate, from the ``.crate`` archive alone.

``cargo publish`` sends, ahead of the compressed crate bytes, a JSON document
describing the release (name, version, dependencies, features, and the package
manifest scalars including the rendered README text). crates.io stores that
document as the crate's index entry. The exact-byte uploader embeds this JSON so
it can perform one deterministic upload without invoking cargo. Producing the
JSON for a new release previously required hand-reconstruction; this module makes
it a reviewed, tested derivation.

The derivation reads the *normalized* ``Cargo.toml`` that cargo writes into the
``.crate`` (all dependencies already resolved to registry requirements) plus the
README file it references, and emits the metadata with cargo's field order,
dependency order (Cargo.toml table order: ``dependencies`` then
``dev-dependencies`` then ``build-dependencies`` then ``target.*``), and compact
JSON separators. Serialization fidelity and derivation faithfulness are proven by
``test_crates_io_registry_metadata`` reproducing shipped metadata byte-for-byte.

The module refuses (raises :class:`RegistryMetadataError`) on any manifest
construct it does not model exactly -- renamed dependencies, alternate
registries, git/path sources -- rather than emit a document that would silently
diverge from what cargo produces. A refusal is a signal to extend this module
(with a fixture) for the new construct, never to guess.
"""
from __future__ import annotations

import io
import re
import tarfile
import tomllib
from collections.abc import Mapping, Sequence
from typing import Any


class RegistryMetadataError(RuntimeError):
    """A manifest construct is unsupported or the archive is malformed."""


# cargo's NewCrate serialization: top-level field order and per-dependency field
# order are fixed by the struct definitions in cargo. These orders are asserted
# against shipped metadata in the test suite.
_METADATA_FIELD_ORDER = (
    "name", "vers", "deps", "features", "authors", "description",
    "documentation", "homepage", "readme", "readme_file", "keywords",
    "categories", "license", "license_file", "repository", "badges", "links",
    "rust_version",
)
_DEP_FIELD_ORDER = (
    "optional", "default_features", "name", "features", "version_req",
    "target", "kind",
)
_KIND_BY_TABLE = (
    ("dependencies", "normal"),
    ("dev-dependencies", "dev"),
    ("build-dependencies", "build"),
)
# A version body: a digit-led token with no whitespace, comma, or wildcard.
_VERSION_BODY = r"[0-9][0-9A-Za-z.+-]*"
# A bare version (no operator) -> cargo emits it as a caret requirement.
_BARE_VERSION_RE = re.compile(rf"\A{_VERSION_BODY}\Z")
# A single comparator already in cargo's canonical, whitespace-free form.
_OPERATOR_REQUIREMENT_RE = re.compile(rf"\A(?:\^|~|=|>=|<=|>|<){_VERSION_BODY}\Z")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryMetadataError(message)


def _read_member(archive: bytes, suffix: str) -> bytes | None:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith("/" + suffix):
                extracted = tar.extractfile(member)
                _require(extracted is not None, f"cannot read {suffix} from crate")
                return extracted.read()
    return None


def _normalize_requirement(spec: Mapping[str, Any] | str, name: str) -> str:
    requirement = spec if isinstance(spec, str) else spec.get("version")
    _require(
        isinstance(requirement, str) and requirement != "",
        f"dependency {name!r} has no version requirement",
    )
    # cargo fills the registry ``version_req`` with semver::VersionReq::to_string(),
    # which strips interior whitespace, joins comma-separated comparators with a
    # single ``", "``, and leaves wildcards (``1.*``) without a caret while turning a
    # bare version into a caret requirement. This module reproduces only the two
    # forms it can canonicalize with certainty:
    #   * a bare version ("0.6" -> "^0.6");
    #   * a single operator-prefixed requirement already in canonical no-whitespace
    #     form ("=0.1.4", "^0.4.1", ">=1.2" stay verbatim).
    # Anything cargo would canonicalize differently -- interior whitespace, a
    # wildcard, or multiple comparators -- is REFUSED rather than emitted wrong, so
    # such a crate is flagged at build time. Extend this function (with a fixture)
    # to faithfully render that form before publishing it.
    if _OPERATOR_REQUIREMENT_RE.match(requirement):
        return requirement
    if _BARE_VERSION_RE.match(requirement):
        return "^" + requirement
    raise RegistryMetadataError(
        f"dependency {name!r} has a version requirement this module does not "
        f"reproduce exactly ({requirement!r}); cargo canonicalizes interior "
        f"whitespace, wildcards, and multi-comparator ranges -- extend "
        f"crates_io_registry_metadata (with a fixture) before publishing it"
    )


def _dependency(name: str, kind: str, spec: Mapping[str, Any] | str,
                target: str | None) -> dict[str, Any]:
    if isinstance(spec, str):
        spec = {"version": spec}
    _require(
        "package" not in spec,
        f"dependency {name!r} is renamed (package=); explicit_name_in_toml is "
        "not modeled -- extend this module with a fixture before publishing it",
    )
    _require(
        "registry" not in spec and "registry-index" not in spec,
        f"dependency {name!r} uses an alternate registry -- unsupported",
    )
    _require(
        "git" not in spec and "path" not in spec,
        f"dependency {name!r} has a git/path source in the normalized manifest -- "
        "unexpected for a published crate",
    )
    return {
        "optional": bool(spec.get("optional", False)),
        "default_features": bool(spec.get("default-features", True)),
        "name": name,
        "features": [str(f) for f in spec.get("features", [])],
        "version_req": _normalize_requirement(spec, name),
        "target": target,
        "kind": kind,
    }


def _dependencies(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for table_name, kind in _KIND_BY_TABLE:
        for name, spec in (manifest.get(table_name) or {}).items():
            deps.append(_dependency(name, kind, spec, None))
    for cfg, tables in (manifest.get("target") or {}).items():
        for table_name, kind in _KIND_BY_TABLE:
            for name, spec in (tables.get(table_name) or {}).items():
                deps.append(_dependency(name, kind, spec, str(cfg)))
    return deps


def _features(manifest: Mapping[str, Any]) -> dict[str, list[str]]:
    features = manifest.get("features") or {}
    _require(isinstance(features, Mapping), "[features] must be a table")
    return {str(k): [str(v) for v in vals] for k, vals in features.items()}


def _reject_unreproduced_optional_features(
    deps: Sequence[Mapping[str, Any]], features: Mapping[str, Sequence[str]]
) -> None:
    """Refuse manifests that would need Cargo's implicit optional-dep features.

    Cargo synthesizes a feature ``name = ["dep:name"]`` for every optional
    dependency NOT referenced through the ``dep:`` prefix somewhere in
    ``[features]``. This module copies only the explicit ``[features]`` table, so
    such a manifest would publish index metadata missing that feature -- consumers
    could not enable the optional dependency. Rather than emit divergent metadata,
    refuse fail-closed; extend this module (with a fixture reproducing Cargo's
    synthesis and its ordering) before publishing such a crate.
    """

    referenced = {
        value[len("dep:"):]
        for values in features.values()
        for value in values
        if value.startswith("dep:")
    }
    for dep in deps:
        if dep["optional"] and dep["name"] not in referenced:
            raise RegistryMetadataError(
                f"optional dependency {dep['name']!r} is not referenced via "
                f"'dep:{dep['name']}' in [features]; Cargo would synthesize an "
                "implicit feature this module does not reproduce -- extend "
                "crates_io_registry_metadata (with a fixture) before publishing it"
            )


def registry_metadata(crate_archive: bytes) -> dict[str, Any]:
    """Return the registry metadata dict for a ``.crate`` archive's bytes."""

    manifest_bytes = _read_member(crate_archive, "Cargo.toml")
    _require(manifest_bytes is not None, "crate archive has no Cargo.toml")
    try:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RegistryMetadataError("crate Cargo.toml is not valid TOML") from exc

    package = manifest.get("package")
    _require(isinstance(package, Mapping), "crate Cargo.toml has no [package]")

    readme_field = package.get("readme")
    readme_file: str | None = None
    readme_text: str | None = None
    if isinstance(readme_field, str):
        readme_file = readme_field
        readme_bytes = _read_member(crate_archive, readme_file)
        _require(
            readme_bytes is not None,
            f"manifest names readme {readme_file!r} but it is absent from the crate",
        )
        try:
            readme_text = readme_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RegistryMetadataError("crate README is not valid UTF-8") from exc

    def scalar(key: str) -> Any:
        value = package.get(key)
        return value if value != "" else None

    metadata: dict[str, Any] = {
        "name": package["name"],
        "vers": package["version"],
        "deps": _dependencies(manifest),
        "features": _features(manifest),
        "authors": [str(a) for a in package.get("authors", [])],
        "description": scalar("description"),
        "documentation": scalar("documentation"),
        "homepage": scalar("homepage"),
        "readme": readme_text,
        "readme_file": readme_file,
        "keywords": [str(k) for k in package.get("keywords", [])],
        "categories": [str(c) for c in package.get("categories", [])],
        "license": scalar("license"),
        "license_file": scalar("license-file"),
        "repository": scalar("repository"),
        "badges": dict(manifest.get("badges") or {}),
        "links": scalar("links"),
        "rust_version": scalar("rust-version"),
    }
    _reject_unreproduced_optional_features(metadata["deps"], metadata["features"])
    _require(
        tuple(metadata) == _METADATA_FIELD_ORDER,
        "internal error: metadata field order drifted",
    )
    return metadata


def serialize_metadata(metadata: Mapping[str, Any]) -> str:
    """Serialize metadata exactly as cargo does: compact separators, raw UTF-8."""

    import json  # local import: this module is import-safe for json.dumps only

    return json.dumps(metadata, separators=(",", ":"), ensure_ascii=False)
