<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# mlkem-native provenance

- Upstream: `https://github.com/pq-code-package/mlkem-native`
- Release: `v1.2.0`, published 2026-06-20
- Commit: `0ba906cb14b1c241476134d7403a811b382ca498`
- Tag status: unsigned lightweight tag
- Immutable archive URL:
  `https://github.com/pq-code-package/mlkem-native/archive/0ba906cb14b1c241476134d7403a811b382ca498.tar.gz`
- Immutable archive SHA-256:
  `f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677`
- Upstream `LICENSE` SHA-256:
  `6393331d41b9fed47a9e18d21b9b844ae8e76bcad8b6da45604c132ae13f3029`
- `git archive --format=tar HEAD mlkem` SHA-256:
  `77603845ef1bc00cfed17635d4d6844bbf2019b656a3baea8ab18041daa74396`
- Vendored subtree: upstream `mlkem/`, 124 regular files, no symlinks

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
