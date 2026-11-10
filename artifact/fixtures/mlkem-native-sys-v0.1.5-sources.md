# Historical ML-KEM source fixture

`mlkem-native-sys-v0.1.5-sources.json` contains the 13 local build/source files
from Git commit `7ed1f96a7ec33732f02a989dd5a4669cdcce39ad`. Each file was checked
against the unchanged 0.1.5 SHA-256 allowlist before this fixture was written.
The fixture is test data, not a compiled or selectable primitive implementation.

Historical mutation tests use these exact bytes so changing the current SDK
does not silently change what an old package receipt accepts. The current crate
has its own source-identity tests and closed alpha.1 profile. Both directions of
cross-version substitution are rejected. Source identity by itself does not
qualify a candidate binary for release, native execution or constant-time claims.
