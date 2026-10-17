<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# mlkem-native provenance

- Upstream: `https://github.com/pq-code-package/mlkem-native`
- Release: `v2.0.0`, published 2026-08-07
- Commit: `d1b2fe782888bdb761a50336012923180be7f502`
- Tag status: unsigned lightweight tag
- Immutable archive URL:
  `https://github.com/pq-code-package/mlkem-native/archive/d1b2fe782888bdb761a50336012923180be7f502.tar.gz`
- Immutable archive SHA-256:
  `7c7a10464ba3c62d5657a70da495539ab7f28e464cff80eb9d8173e2bc91c4d3`
- Upstream `LICENSE` SHA-256:
  `1c730e3c2cd4f70e058519ef3e910d8bdd4ed822ae2ce689f3c63d32fc52314b`
- `git archive --format=tar HEAD mlkem` SHA-256:
  `1f0a7c35241f07dae424d197d7b8e8a2742f070fb1d75fa7aecb1846e6686d2e`
- Vendored subtree: upstream `mlkem/`, 125 regular files, no symlinks

The Git tag and commit have no cryptographic signature. The full commit ID and
archive hash above are therefore the trust anchors for this import. The
per-file inventory in `INVENTORY.sha256` is generated from the verified
archive and is checked independently by `scripts/verify-vendor.py`.

The vendored subtree is byte-for-byte upstream source. Q-Periapt integration
code lives only under this crate's `src/` directory; upstream files are not
patched. Updating the pinned revision requires changing the constants in the
update and verification scripts, reviewing the upstream diff and assurance
boundary, regenerating this document, and rerunning the complete release
verification.
