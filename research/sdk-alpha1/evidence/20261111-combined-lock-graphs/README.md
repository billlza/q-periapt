# Combined FIPS 204 and rustix dependency qualification

The five current Cargo graphs were resolved with `cargo metadata --locked` after the FIPS 204 0.5.0 migration, Android ABI license-union repair, and rustix 1.1.6 security update were combined. All five selected FIPS 204 0.5.0; all four graphs containing rustix selected 1.1.6. The fuzz graph does not contain rustix. All five lock bytes and all 44 recorded index inputs stayed unchanged through the commands.

The same final five locks then passed the fixed RustSec advisory scan with the authenticated cargo-audit 0.22.2 binary and `--deny warnings`, without ignored advisories. This is the advisory phase of the existing production audit; its separate exact sparse-index checksum and yanked-state gate remains unchanged. The raw metadata, command receipts and audit logs are retained here.

The backend source subtree matches the source of the retained 73-test FIPS execution exactly. The five AAR implementation/test blobs match the independently reviewed and revalidated recovery commit. The added evidence files leave the validated source inputs unchanged. Full hosted platform and release admission runs bind the subsequently published candidate.
