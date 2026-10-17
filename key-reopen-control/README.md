# Windows key reopen regression control

This isolated branch checks an exact product commit on native Windows. It first
runs two unchanged regression tests, then selects the retained old non-Unix
fallback bodies by restoring their previous platform gates. No assertion or
test input is changed. The control succeeds only if both owners are observed
returning after file synchronization without parent synchronization, and the
two sync-order assertions fail for that exact reason. Compile failures and
unrelated failures do not satisfy the control.

The mutation is restricted to two files in a disposable CI checkout, recorded,
and restored. This is a controlled reconstruction of the old branch selection,
not qualification of a complete historical release. Do not merge this probe
history into the SDK.
