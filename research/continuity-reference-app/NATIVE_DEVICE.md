# Native device enrollment and publication

`q-periapt-native-device` is a reference consumer of the public native enrollment
owner. It uses current OS time and the SDK's controlled signer, journal and
recoverable publication operations. It contains no issuer, test authority or
clock override. Account authentication and device approval belong to the host;
the optional Passkey host is one source of these inputs.

The first-use host supplies an independently approved `Invitation`, a current
`RootInfo`, and separate `qperiapt-policy-pins/1` and
`qperiapt-policy-materials/1` documents. These are the existing reference-host
and policy-publisher formats. A received certificate or publication cannot choose
the trust inputs. Keep the selected invitation: the SDK binds its root, device,
generation, family and validity to the original storage. Application correlation
and reapproval records remain in the host. An explicit same-intent reapproval
may select its separately approved host operation without replacing the device.

Use canonical absolute paths beneath existing private directories. The tool
does not create directories or repair their permissions. Provision the wrapping
key once, retain it separately from journal backups, and reuse that exact file.
A missing key, busy owner or damaged database is an error; `open` never becomes
first use.

```sh
q-periapt-native-device provision-key "$wrapping_file"
q-periapt-native-device begin "$device_dir" "$wrapping_file" "$invitation"
q-periapt-native-device request "$device_dir" "$wrapping_file" "$invitation" "$request_output"
```

Submit that request through the host's authenticated approval flow. The request
proves possession of the newly controlled device key, not account membership.
After issuance, supply its result and independently current membership:

```sh
q-periapt-native-device accept "$device_dir" "$wrapping_file" "$invitation" \
  "$issued" "$current_root" "$policy_pins" "$policy_materials"
q-periapt-native-device prepare "$device_dir" "$wrapping_file" "$invitation" \
  "$current_root" "$policy_pins" "$policy_materials"
q-periapt-native-device activate "$device_dir" "$wrapping_file" "$invitation" \
  "$current_root" "$policy_pins" "$policy_materials" none
```

`none` is accepted only for a signed local-only policy. A required witness returns
its original subject and image commitment from `prepare`. Obtain independent
witness enrollment, then pass the explicit witness address to `activate`. The
witness key must match the independently supplied policy pin; omission does not
enable local operation. The reference TCP witness carrier authenticates messages
but does not encrypt their metadata.

`status` reopens the original enrollment and reports persisted progress, signing
identity and journal identity. Its `Active` phase is historical metadata, not a
current permission receipt. No request output is overwritten. If output writing
fails after a request commit, retry `request` to a fresh private destination to
retrieve the same bytes.

Before installation selection, `extend` consumes an independently approved
`CredentialExtensionRequest`, its exact issued response, current membership and
live policy. It preserves the original invitation/key/journal and delegates to
the SDK's same-key extension transaction. A new expiry is a new host authorization.
The CLI does not issue it or infer it from a server response.

```sh
q-periapt-native-device extend "$device_dir" "$wrapping_file" "$invitation" \
  "$approved_extension" "$issued_extension" "$current_root" "$policy_pins" "$policy_materials"
```

`prepare`, `activate`, and `refresh-roster` check the retained certificate against
the supplied current signed roster. A newer roster uses the original CAS
coordinator. Positively tracked Unprepared records can advance without creating
children or changing policy. A selected but not activated installation cannot be
retargeted through that transition. Legacy Untracked records require explicit
history reconciliation; missing files never establish first use. Retained
witnessed roster changes need their existing explicit witness coordination, which
this CLI does not submit automatically.

## Recoverable public advertisement

After preparation, `publication-next` observes the original journal's next
publication ID. Retain it independently, then submit that same ID and plan for
every retry. It does not reserve a different ID after an error.

```sh
q-periapt-native-device publication-next "$device_dir" "$wrapping_file" "$invitation" \
  "$current_root" "$policy_pins" "$policy_materials" none
q-periapt-native-device publish "$device_dir" "$wrapping_file" "$invitation" \
  "$current_root" "$policy_pins" "$policy_materials" none \
  "$publication_id_base64url" "$plan" "$empty_private_export_dir"
```

The plan is a strict JSON object with `schema` equal to
`qperiapt-native-publication-plan/1`, an independently selected nonzero 32-byte
`directory` array, and explicit Unix-second `valid_from` / `valid_until` values.
The schema selects reusable classical and PQ members. The signed policy must
permit that profile. Static inputs and the output directory are checked before
device activation; the SDK samples current time again at publication boundaries.

The single durable `publication.json` output has schema
`qperiapt-native-publication/1`, original journal and publication identities, the
unchanged `QPPUBA01` artifact, retained certificate/roster bytes and their checkpoint.
Binary fields are canonical base64url without padding. These bytes are public
distribution, not trust pins or proof of remote directory publication. Consumers
must verify signatures, exact expected identity/directory, membership and current
policy/time before constructing a connection.

A partial or failed export does not undo a committed publication. Keep the
original ID and plan, reopen the same device, and retry to another empty export
directory. The prepared artifact and inventory identities are reused; the tool
does not export private keys.

This entry point covers native first use, preinstallation extension, supported
same-credential roster refresh and local public advertisement. The
[session exchange CLI](NATIVE_SESSION.md) adds owned responder operations and a
durable reference inbox. A bidirectional network service, later lifecycle coordination and legacy
Accepted migration remain separate work. CLI tests use real subprocesses and OS
time with explicitly generated test authority. The real user account and its
device grants are not modified by those tests.

## Inspect an original retained-state renewal request

Once an installation is active, extending a certificate alone cannot authorize
its retained keys, publications or sessions. The SDK's separate root-signed G
grant binds the original storage owner, policy and exact previous credential and
roster. Obtain its public issuer inputs from the original owner:

```sh
q-periapt-native-device renewal-request "$device_dir" "$wrapping_file" "$invitation" \
  "$retained_renewal_id" "$original_policy_pins" "$original_policy_materials" \
  none "$new_request_output"
```

Choose and retain a nonzero 32-byte base64url renewal ID before the call. The
output uses `qperiapt-retained-credential-request/1` and contains public original
and previous certificate/roster bytes, journal and owner identities, policy
checkpoints and the previous checkpoint actually observed in the journal. It
does not contain private keys. A required-witness installation needs its explicit
witness address instead of `none`, with the pinned witness key from the original
policy inputs. There is no automatic local fallback.

The command verifies exact signed historical policy and SDK bindings without
backdating or returning a live policy owner. It can inspect an expired original
credential; the local profile does not require its private signing file. Pending
maintenance, a different original policy, unprepared installation or inconsistent
history still fails. The SDK may reconcile retained completion receipts while
opening the matched history; this is not a generic raw database reader.

Request inspection does not reserve the observed predecessor or grant permission.
Keep the exact exported request and operation before submission. Output files
are exclusive; retry to a fresh filename if an export outcome is unknown. If
another operation changed the observed history, do not silently submit a changed
request under the old approval. The account issuer must authenticate the user,
check its own membership/issuance records and serialize and retain the exact G
decision. Host G issuance and native staging/activation are still separate
integration work; this export alone cannot restore an expired endpoint.
