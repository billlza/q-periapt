# Original device creation recovery

Source `e942693b99bf51df85f27e61a554fa06e7aa9eb7` repairs the process interruption
between syncing a complete initial device transaction and its formal rename.
Registration alone opts into one reserved `.stage-initial-intent` slot. Recovery
verifies its original scope, MAC, zero predecessor and revision-one target before
publishing the exact original bytes. Active readers and session/configuration
creation retain their prior contract; no private seed is copied to configuration.

The regression first failed with `MissingState` on the previous random staging
layout. That source and failed state are preserved. Current source and a separately
built/installed wheel pass client16 and adapter8 checks. The installed client
executes14 real SIGKILL cuts, including repeated initial-publication recovery
without allocating new orphans. It also refuses corruption, truncation, wrong
key/identity, arbitrary authenticated orphans, repeated provision and advanced
transactions placed in the initial slot. Tests and failures are not skipped.

The same retained Accepted client from the previous installed f0b861e2 package
was opened with its original key/ID by the old package and new source. Public
identity and all state-file hashes remained identical. This was historical-state
compatibility, not a new permission or backdated acceptance.

Related registration/session integration passed42 local workers/10 process kills
and50 witness workers/11 kills against the retained native counterpart with
SHA256 `60c66db3973b9e1d8aabc22e3a87345b49e0a6d5ea080b1e855c6bbaf1e553fa`.
That binary comes from qualified build b89eb724 against SDK base23280124; its
native fixture sources still match. This is a frozen native reference endpoint,
not a new native build. It verifies original enrollment, traffic, rekey, renewal,
pending recovery and lifetime behavior with fixture authority/time controls.

The earlier [hosted client run39214488459](https://github.com/billlza/q-periapt/actions/runs/39214488459)
completed at32692f3d on Linuxx86_64 and AppleSilicon. Both terminal40-member
artifacts were checked against GitHub digests,67 source inputs and the installed
50-module wheel. Both passed client10/adapter8, Node17 and Rust26 debug/release
entries. Those hosted checks precede this recovery fix and do not qualify it.
No live CI logs were read and no downloaded code was executed during artifact readback.

The capture includes source, public check outputs, old/new regression results,
local inspected wheel and earlier hosted archives. Private fixtures, wrapping
keys and encrypted device/session images remain outside it. Hashes identify the
retained original files without exposing their contents.

A crash before any complete original device record exists remains an explicit
failure. Truncated records and older random staging files are not regenerated or
silently migrated. Authorized abandonment/restart, operational policy publication,
real host-to-installed-client authorization, full session CLI, power-loss/erasure/
PCS analysis and remaining0.2.0 release requirements stay open.
