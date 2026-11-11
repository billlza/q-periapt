# Hosted Python namespace regression: Apple Silicon

[Run 39184186420](https://github.com/billlza/q-periapt/actions/runs/39184186420),
job 117843019529, succeeded at
`115fb323c9082f4db573ff2fdbb17c75c4c3f372`.

The new `qperiapt_continuity_reference` source namespace completed all nineteen
reference lanes against the installed native counterpart and public importer.
All twelve readbacks passed on their first execution. Current source inventory
walks and imports use the new package name; historical `peer/state_codec.py`
archive keys are preserved. This covers the historical codec, process recovery,
control, renewal, revocation and registration cases after the namespace move.

The terminal artifact is 53,507,369 bytes, with digest
`sha256:7bfd393575d0fbb57b667a7cef1a9adf1ed918bf28c17bb9d5be0ad835b36c50`. `CAPTURE.zip` and `SOURCE.zip` are disjoint and
covered by the full manifest in `CAPTURE.zip`. Each is below 50 MiB. The frozen
build-source archive is shared by hash with the other platform. Uploaded
executables were not run locally during readback.

This head still runs Python from source. The next entry-point change adds real
wheel installation and registered-owner execution to CI; this receipt does not
claim that later hosted result. Private-state checks remain producer runtime
observations, and deployed account authentication, cross-host transport,
multidevice completion, PCS, energy and release admission remain open.
