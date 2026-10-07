# Protected signing owners

The candidate's account-root, device, protocol-policy and witness signing owners support
immutable encrypted files through `provision` and `open`. This provides software
key persistence before enrollment, independently of the device journal that needs
an already verified credential. The existing volatile `generate` API remains
available. There is no private-key export, arbitrary-message signing API or public
constructor from raw signing seeds.

## Provisioning and admission

Retain a fresh `SigningKeyId` in trusted configuration before provisioning its
file. Use one ID per owner file; do not learn the expected ID from the file being
opened. The ID is public correlation data and never key-generation entropy.
Protect the `JournalKey` wrapping-key file separately from encrypted-key/database
backups. All key generation uses the platform CSPRNG and the existing fixed
ML-DSA-65 plus P-256 composition. P-256 scalar rejection sampling is bounded at
eight attempts; failures return no owner.

`provision` prepares the complete sealed image in memory, writes it into a fresh
private staging inode, syncs that inode, and publishes it through descriptor-relative
NOREPLACE rename. It authenticates the published inode and syncs the pinned parent
before returning the signing owner. Existing destinations, including old partial
files, are never replaced. Unsupported rename operations fail without a fallback.
Before success, neither a public enrollment key nor a signing owner is released.

On returned errors, no file is deleted. Checking inode identity and then unlinking
a name is not an atomic conditional deletion. The original error retains the
attempted staging name as diagnostic data, not deletion authority.
The destination is never removed, even when directory sync or result delivery
fails: another opener may already have reconciled it and used the identity.
A crash before rename can leave a private `.private-publication-*` orphan. These
files are not recovery authority and are never selected or automatically swept.
Only an explicit original first-use intent with an absent destination may retry
with fresh unpublished material. A previously active missing key is data loss.
Database genesis now shares the staged publication capability. Orphan cleanup,
physical erasure and old partial-state recovery remain separate lifecycle work;
applications must bound explicit first-use retries.

`open` requires an existing exact-size private file, the independently expected
ID, the same role and the protected wrapping key. It authenticates the full image,
reconstructs both signing keys and compares both public components against the
encrypted public record. It syncs the admitted inode and its pinned parent before
returning an owner, including when reconciling a complete first write whose return
was lost. Missing, zero-length, truncated, extended, corrupted or mismatched files
are errors; they do not invoke key generation. A partial file remains explicit
failed provisioning rather than an implicit new identity.

The shared adapter admits private descriptor-relative paths with no symlink
traversal and exact owner/mode/ACL checks. The signing provider additionally
requires a single hard link. Parent-directory sync rechecks private ownership and
mode on the pinned descriptor. The reviewed private-file publication adapter supports macOS/Linux;
other platforms fail admission. Same-UID host control is trusted. Files are
immutable after initialization, so opening another owner does not mutate or rotate
the key. `close` affects that in-memory owner, not every independently opened copy.

## Exact encoding

The file is exactly **2138 bytes**:

`QPSIGN01[8] || role:u8 || identity[32] || nonce[24] || ciphertext[2057] || tag[16]`

Roles are root=1, device=2, protocol-policy=3 and witness=4. The full 65-byte header is
XChaCha20-Poly1305 associated data. A new OS-random nonce is chosen for the one
initial sealing operation. HKDF-SHA256 with default zero salt and info
`Q-PERIAPT-CONTINUITY-SIGNING-OWNER-KEY/v1` derives a distinct 32-byte encryption
key from the protected journal wrapping key. This key is separate from journal
image and SDK sealed-operation encryption keys.

The encrypted plaintext is:

`QPSMAT01[8] || ML-DSA-65_seed[32] || P-256_scalar[32] || public_pair[1985]`

The public pair is the existing ML-DSA-65 public[1952] plus canonical compressed
P-256 public[33]. Invalid scalars and seed/public mismatch fail even for an
authenticated image. Seeds, decrypted buffers, derived wrapping keys and expanded
key owners use the existing zeroizing types. They do not establish physical-page,
backup, swap or complete compiler-temporary erasure. The outer role, ID and fixed
extent remain visible.

## Bootstrap recovery and verification

Enroll only the public key returned by successful provisioning. On restart, open
the protected owner and pass it to the existing journal recovery API. The journal
still checks its verified device, exact signing purpose/body and saved randomness.
Restoring a file does not grant a new credential, roster, policy or operation.
Pinned result replay retains its existing signer-free path. Signing-owner
persistence does not change bootstrap network or ABI bytes.

Tests cover all four roles, owner close/reopen, role/identity/wrapping-key
substitution, every byte of the sealed file, length and scalar/public mismatch,
unsafe filesystem shapes, and exact saved-signature replay. Native process cuts
cover generated-but-unpublished and durably-published-before-return owners. The
shared publication suite additionally kills children with partial staging contents,
complete staging contents, synced staging contents, after rename and after parent
sync; no partial image becomes the destination. Two more cuts interrupt a real responder before and after its
reserved signature computation. The original owner dies with the process; the
surviving actual initiator verifies the reopened owner's response and final MAC.
The post-computation case also compares the exact recovered signature bytes.

Key rotation, credential-generation replacement, root migration, durable global
revocation, hardware-keystore adapters, rollback anchors and the complete backup/
erasure model remain part of the wider 0.2.0 lifecycle work. Closing a software owner
or removing a file is not a claim that copies in backups can no longer be used.
