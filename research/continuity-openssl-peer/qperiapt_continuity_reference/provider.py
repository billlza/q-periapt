"""Load only the explicitly selected independent provider, without site/.pth."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from pathlib import Path
import importlib.util
import sys


def load_provider(directory: Path):
    root = directory.resolve(strict=True)
    if not root.is_dir() or not (root / "cryptography").is_dir():
        raise ValueError("missing explicit cryptography provider directory")
    sys.path.append(str(root))
    spec = importlib.util.find_spec("cryptography")
    if spec is None or spec.origin is None or not Path(spec.origin).resolve(strict=True).is_relative_to(root):
        raise ValueError("provider would load outside the selected directory")
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.bindings import _rust
    if cryptography.__version__ != "48.0.1":
        raise ValueError("unqualified cryptography version")
    for module in (cryptography, _rust):
        if not Path(module.__file__).resolve(strict=True).is_relative_to(root):
            raise ValueError("provider loaded outside the selected directory")
    return cryptography, backend
