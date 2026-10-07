#!/usr/bin/env python3
"""Download one code-pinned formal-tool asset through bounded I/O."""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import stat
import sys
import tempfile
import time
from collections.abc import Callable
from types import MappingProxyType
from typing import NoReturn

from bounded_process import BoundedProcessError, BoundedResult, write_stdout_at
from evidence_io import EvidenceIOError, consume_regular_snapshot_at


@dataclasses.dataclass(frozen=True, slots=True)
class FormalToolAsset:
    """One immutable public binary used by a formal-proof CI job."""

    url: str
    sha256: str
    size: int
    leaf: str


ASSETS = MappingProxyType(
    {
        "maude-3.5.1": FormalToolAsset(
            url=(
                "https://github.com/maude-lang/Maude/releases/download/"
                "Maude3.5.1/Maude-3.5.1-linux-x86_64.zip"
            ),
            sha256=(
                "72ed1ca87e3b3d0dfc6ee1436baf154b"
                "f04c45ff97d521bec040c5e8dfc8f92c"
            ),
            size=2_893_486,
            leaf="Maude-3.5.1-linux-x86_64.zip",
        ),
        "tamarin-1.12.0": FormalToolAsset(
            url=(
                "https://github.com/tamarin-prover/tamarin-prover/releases/download/"
                "1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz"
            ),
            sha256=(
                "201be06f469e47cff554df6ca93db8366"
                "fc2c69d70c61fcbd1370a1074b469c6"
            ),
            size=13_048_539,
            leaf="tamarin-prover-1.12.0-linux64-ubuntu.tar.gz",
        ),
        "opam-2.5.2": FormalToolAsset(
            url=(
                "https://github.com/ocaml/opam/releases/download/"
                "2.5.2/opam-2.5.2-x86_64-linux"
            ),
            sha256=(
                "edfca2630c373b44b7ee1c2f81cd8dcf"
                "67468d0db57d6c02158de553ac63dbd4"
            ),
            size=8_945_008,
            leaf="opam-2.5.2-x86_64-linux",
        ),
    }
)

_CURL = "/usr/bin/curl"
_CURL_ENVIRONMENT = MappingProxyType(
    {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
)
_ATTEMPTS = 3
_RETRY_DELAYS_SECONDS = (15, 30)
_BOUND_TIMEOUT_SECONDS = 300
_CURL_MAX_TIME_SECONDS = 270
_DIRECTORY_PREFIX = "qperiapt-formal-tool-asset."
_LINUX_TEMPORARY_PARENT = pathlib.Path("/tmp")
# Tests replace this private constant with one current-user-owned mode-0700
# directory. Production callers have no path-selection API.
_FIXED_TEMPORARY_PARENT = _LINUX_TEMPORARY_PARENT


class FormalToolAssetError(RuntimeError):
    """A pinned formal-tool asset could not be downloaded and verified."""


def _fail(message: str) -> NoReturn:
    raise FormalToolAssetError(message)


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _linux_temporary_parent_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o1777
    ):
        _fail(
            "formal-tool production temporary parent must be the root-owned "
            "mode-01777 /tmp directory"
        )


def _private_test_parent_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail(
            "formal-tool test temporary parent must be a current-user-owned "
            "mode-0700 directory"
        )


def _private_directory_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail("formal-tool temporary directory must be current-user-owned mode 0700")


def _private_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError(
            "formal-tool asset must be one current-user-owned regular file "
            "with one link and mode 0600"
        )


def _fixed_temporary_parent() -> pathlib.Path:
    candidate = _FIXED_TEMPORARY_PARENT
    if not isinstance(candidate, pathlib.Path) or not candidate.is_absolute():
        _fail("formal-tool fixed temporary parent must be one absolute path")
    production = candidate == _LINUX_TEMPORARY_PARENT
    if production and sys.platform != "linux":
        _fail("formal-tool asset downloads require Linux with fixed /tmp storage")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = os.lstat(candidate)
    except OSError as exc:
        raise FormalToolAssetError(
            f"formal-tool temporary parent is unavailable: {candidate}: {exc}"
        ) from exc
    if candidate != resolved:
        _fail(
            "formal-tool fixed temporary parent must be canonical and contain no "
            "symlink components"
        )
    if production:
        _linux_temporary_parent_metadata(metadata)
    else:
        _private_test_parent_metadata(metadata)
    return candidate


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _require_directory_path_identity(
    directory: pathlib.Path,
    expected_identity: tuple[int, int],
    expected_parent: pathlib.Path,
) -> None:
    if (
        directory.parent != expected_parent
        or not directory.name.startswith(_DIRECTORY_PREFIX)
        or directory.name == _DIRECTORY_PREFIX
    ):
        _fail("formal-tool temporary directory is outside the fixed parent")
    try:
        metadata = os.lstat(directory)
    except OSError as exc:
        raise FormalToolAssetError(
            f"formal-tool temporary directory became unavailable: {directory}: {exc}"
        ) from exc
    _private_directory_metadata(metadata)
    if _identity(metadata) != expected_identity:
        _fail("formal-tool temporary directory path changed during the download")


def _create_private_directory(
    parent: pathlib.Path,
) -> tuple[pathlib.Path, int, tuple[int, int]]:
    directory = pathlib.Path(
        tempfile.mkdtemp(prefix=_DIRECTORY_PREFIX, dir=os.fspath(parent))
    )
    directory_fd = -1
    primary: BaseException | None = None
    try:
        directory_fd = os.open(directory, _directory_open_flags())
        os.fchmod(directory_fd, 0o700)
        metadata = os.fstat(directory_fd)
        _private_directory_metadata(metadata)
        identity = _identity(metadata)
        _require_directory_path_identity(directory, identity, parent)
        return directory, directory_fd, identity
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if primary is not None:
            cleanup_failures: list[str] = []
            if directory_fd >= 0:
                try:
                    os.close(directory_fd)
                except BaseException as exc:
                    cleanup_failures.append(f"close rejected directory: {exc}")
            try:
                os.rmdir(directory)
            except BaseException as exc:
                cleanup_failures.append(f"remove rejected directory: {exc}")
            if cleanup_failures:
                primary.add_note(
                    "formal-tool directory cleanup also failed: "
                    + "; ".join(cleanup_failures)
                )


def _curl_argv(asset: FormalToolAsset) -> tuple[str, ...]:
    return (
        _CURL,
        "-q",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "30",
        "--max-time",
        str(_CURL_MAX_TIME_SECONDS),
        "--max-filesize",
        str(asset.size),
        asset.url,
    )


def _target_absent(directory_fd: int, leaf: str) -> None:
    try:
        os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise FormalToolAssetError(
            f"cannot inspect formal-tool retry target {leaf}: {exc}"
        ) from exc
    _fail(f"formal-tool retry target unexpectedly exists: {leaf}")


def _open_cleanup_directory(
    directory: pathlib.Path,
    expected_identity: tuple[int, int],
    expected_parent: pathlib.Path,
) -> int:
    _require_directory_path_identity(directory, expected_identity, expected_parent)
    descriptor = os.open(directory, _directory_open_flags())
    try:
        metadata = os.fstat(descriptor)
        _private_directory_metadata(metadata)
        if _identity(metadata) != expected_identity:
            _fail("formal-tool temporary directory changed while reopening it")
    except BaseException as primary:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            primary.add_note(
                "closing the rejected formal-tool directory also failed: "
                f"{cleanup_error}"
            )
        raise
    return descriptor


def _cleanup_failed_download(
    directory_fd: int,
    directory: pathlib.Path,
    leaf: str,
    expected_identity: tuple[int, int],
    expected_parent: pathlib.Path,
) -> list[str]:
    failures: list[str] = []
    cleanup_fd = directory_fd
    if cleanup_fd < 0:
        try:
            cleanup_fd = _open_cleanup_directory(
                directory, expected_identity, expected_parent
            )
        except BaseException as exc:
            failures.append(f"reopen asset directory: {exc}")
    if cleanup_fd >= 0:
        try:
            os.unlink(leaf, dir_fd=cleanup_fd)
        except FileNotFoundError:
            pass
        except BaseException as exc:
            failures.append(f"remove formal-tool asset: {exc}")
        try:
            os.close(cleanup_fd)
        except BaseException as exc:
            failures.append(f"close asset directory: {exc}")
    try:
        _require_directory_path_identity(
            directory, expected_identity, expected_parent
        )
    except BaseException as exc:
        failures.append(f"retain changed asset directory path: {exc}")
    else:
        try:
            os.rmdir(directory)
        except FileNotFoundError:
            pass
        except BaseException as exc:
            failures.append(f"remove asset directory: {exc}")
    return failures


def _retry_message(
    asset_name: str,
    reason: str,
    delay_seconds: int,
) -> None:
    print(
        f"{asset_name} {reason}; retrying in {delay_seconds} seconds",
        file=sys.stderr,
    )


def download(
    asset_name: str,
    *,
    runner: Callable[..., BoundedResult] = write_stdout_at,
    sleeper: Callable[[float], None] = time.sleep,
) -> pathlib.Path:
    """Download, byte-bound, and hash one fixed formal-tool asset."""

    asset = ASSETS.get(asset_name)
    if asset is None:
        _fail("formal-tool asset is not in the fixed allowlist")
    parent = _fixed_temporary_parent()
    directory, directory_fd, directory_identity = _create_private_directory(parent)
    success = False
    primary: BaseException | None = None
    try:
        for attempt in range(1, _ATTEMPTS + 1):
            _target_absent(directory_fd, asset.leaf)
            try:
                result = runner(
                    _curl_argv(asset),
                    output_directory_fd=directory_fd,
                    output_name=asset.leaf,
                    timeout_seconds=_BOUND_TIMEOUT_SECONDS,
                    maximum_bytes=asset.size,
                    stderr=None,
                    environment=_CURL_ENVIRONMENT,
                )
            except BoundedProcessError as exc:
                if exc.kind != "timeout":
                    raise
                _target_absent(directory_fd, asset.leaf)
                if attempt == _ATTEMPTS:
                    raise FormalToolAssetError(
                        f"{asset_name} download timed out on all {_ATTEMPTS} attempts"
                    ) from exc
                delay = _RETRY_DELAYS_SECONDS[attempt - 1]
                _retry_message(asset_name, "download timed out", delay)
                sleeper(delay)
                continue

            if (
                not isinstance(result, BoundedResult)
                or type(result.returncode) is not int
            ):
                _fail("formal-tool download runner returned a malformed result")
            if result.returncode != 0:
                _target_absent(directory_fd, asset.leaf)
                if attempt == _ATTEMPTS:
                    _fail(
                        f"{asset_name} download failed after {_ATTEMPTS} attempts "
                        f"with curl status {result.returncode}"
                    )
                delay = _RETRY_DELAYS_SECONDS[attempt - 1]
                _retry_message(
                    asset_name,
                    f"curl status {result.returncode}",
                    delay,
                )
                sleeper(delay)
                continue

            snapshot = consume_regular_snapshot_at(
                directory_fd,
                asset.leaf,
                display_path=directory / asset.leaf,
                maximum=asset.size,
                label=f"{asset_name} formal-tool asset",
                validate_metadata=_private_file_metadata,
            )
            if snapshot.size != asset.size:
                _fail(
                    f"{asset_name} size mismatch: expected {asset.size}, "
                    f"got {snapshot.size}"
                )
            if snapshot.sha256 != asset.sha256:
                _fail(f"{asset_name} SHA-256 mismatch")
            descriptor_metadata = os.fstat(directory_fd)
            _private_directory_metadata(descriptor_metadata)
            if _identity(descriptor_metadata) != directory_identity:
                _fail("formal-tool directory descriptor identity changed")
            _require_directory_path_identity(
                directory, directory_identity, parent
            )
            owned_fd = directory_fd
            directory_fd = -1
            os.close(owned_fd)
            success = True
            return directory / asset.leaf
        _fail(f"{asset_name} download exhausted its bounded attempts")
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if not success:
            cleanup_failures = _cleanup_failed_download(
                directory_fd,
                directory,
                asset.leaf,
                directory_identity,
                parent,
            )
            if cleanup_failures:
                details = "; ".join(cleanup_failures)
                if primary is None:
                    raise FormalToolAssetError(
                        f"formal-tool asset cleanup failed: {details}"
                    )
                primary.add_note(
                    f"formal-tool asset cleanup also failed: {details}"
                )


def _cleanup_published_download(
    path: pathlib.Path,
    asset: FormalToolAsset,
) -> list[str]:
    try:
        fixed_parent = _fixed_temporary_parent()
    except BaseException as exc:
        return [f"validate fixed temporary parent: {exc}"]
    if (
        not path.is_absolute()
        or path.name != asset.leaf
        or not path.parent.name.startswith(_DIRECTORY_PREFIX)
        or path.parent.name == _DIRECTORY_PREFIX
        or path.parent.parent != fixed_parent
    ):
        return ["refusing to clean an unexpected published asset path"]
    try:
        directory_metadata = os.lstat(path.parent)
        _private_directory_metadata(directory_metadata)
        identity = _identity(directory_metadata)
        descriptor = _open_cleanup_directory(path.parent, identity, fixed_parent)
    except BaseException as exc:
        return [f"open published asset directory: {exc}"]
    return _cleanup_failed_download(
        descriptor,
        path.parent,
        asset.leaf,
        identity,
        fixed_parent,
    )


def _error_text(exc: BaseException) -> str:
    details = str(exc)
    notes = getattr(exc, "__notes__", ())
    if notes:
        details += "; " + "; ".join(str(note) for note in notes)
    return details


def _publish_path(path: pathlib.Path) -> None:
    record = f"{path}\n"
    written = sys.stdout.write(record)
    if written != len(record):
        raise OSError("could not write the complete formal-tool asset path")
    sys.stdout.flush()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asset", choices=sorted(ASSETS), required=True)
    args = parser.parse_args(argv)
    asset = ASSETS[args.asset]
    try:
        path = download(args.asset)
    except (
        BoundedProcessError,
        EvidenceIOError,
        OSError,
        FormalToolAssetError,
    ) as exc:
        print(f"error: formal-tool asset: {_error_text(exc)}", file=sys.stderr)
        return 1
    try:
        _publish_path(path)
    except BaseException as exc:
        cleanup_failures = _cleanup_published_download(path, asset)
        if cleanup_failures:
            exc.add_note(
                "formal-tool stdout failure cleanup also failed: "
                + "; ".join(cleanup_failures)
            )
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
