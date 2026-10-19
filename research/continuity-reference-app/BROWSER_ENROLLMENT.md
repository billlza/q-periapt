# Browser approval and original-operation recovery

The optional local reference application now exposes its host enrollment
transactions in the browser. It does not make signup or Passkeys an SDK
requirement. The host operator must first enable the existing enrollment schema
with an independently selected real policy family. The page neither upgrades
storage nor invents a family or policy to make a device appear admitted.

## Operator flow

1. Sign in as the application account. Explicitly prepare or reopen its original
   root, or read its current root/roster. Review the displayed root fingerprint.
2. Create an invitation. The browser saves a nonzero correlation before sending
   the request. Save the invitation and transfer it through the deployment's
   authenticated provisioning channel. A received invitation is not itself an
   independent trust anchor for a device.
3. The original device owner generates and retains its signing keys and signed
   request. Load that public binary request into this page. Selecting a file only
   previews it; an unsubmitted selection can be corrected or discarded. Review
   the device, validity, policy family, root and request fingerprint.
4. Explicitly approve. The browser retains the exact request before sending the
   approval. From this point it cannot substitute another request under the same
   operation. Issue or recover the credential, then export the original result.
   Client acceptance still verifies its original key, independently authenticated
   current identity/roster expectations, live signed policy and trusted time.
5. After interruption, select the original operation and recover/refresh it. If
   the invitation response was lost, the original correlation is retried. Server
   restart requires a new login to the same account. It never requires replacing
   the device identity or resetting the server/client stores.

For a roster conflict or expired host approval, read and review the current
root/roster, then explicitly reapprove against that displayed predecessor. Save
the new correlation before sending. Retries keep that exact predecessor and
request even if a newer observation exists. If that decision is rejected as stale,
select its original source and explicitly approve a new decision against a newly
reviewed roster; keep the failed attempt and its correlation. This does not create
another device. The host atomically admits at most one successor of that source.
Reapproval preserves an already approved key, the device description and original
credential interval; it cannot renew an expired credential. An unapproved source
has not yet established an approved key: a separately selected proof can be sent
as a new reapproval, without overwriting its original submitted request. If the
source became Approved concurrently, the host requires the exact approved proof
and rejects a replacement. Historical Reapproved status does not automatically follow its
successor. Selecting the recorded successor is a separate operator action.

An Issued status has two distinct outputs: the original response and a current
host root/roster observation. They have separate export buttons. Historical
issuance, including after suspension or a newer roster, never grants current
traffic permission. A downloaded observation still needs the deployment's
independent trust channel and policy; it cannot authenticate itself.

## Browser storage and concurrency

Recovery records contain public invitation/request metadata and correlation
identities, not private signing keys or login cookies. They stay in this browser's
local storage after sign-out and are bound to the exact origin and application
account. The signed request alone grants no host account authority. Backups can
be imported only for that same origin/account; conflicting records are rejected,
never overwritten. Corrupt or inaccessible records fail explicitly. Reading a
new empty cache does not create a device; a new invitation always needs an
explicit action. An unresolved initial invitation prevents another new-device
invitation; retained failed reapproval attempts do not prevent a separately
authorized decision for the same original source.

The page coordinates account and enrollment actions across tabs with one
same-origin Web Lock. Writes are synchronous and read back before a request is
sent. A write failure before sending prevents the request; a failure saving a
returned invitation leaves its original pending correlation for retry. These
browser observations are not a power-loss durability promise. Clearing or
rolling back browser storage is not a supported device-recovery procedure;
retain backups and the actual original device store. The host's database remains
the authoritative transaction history.

Records are bounded at 512 operations and 4 MiB, imported device requests at 8192
bytes and HTTP responses at 256 KiB. Quota exhaustion is an error, not a reason
to discard unresolved history. Timeout/disconnection does not cancel a running
host transaction; its original status must be reconciled. There is no automatic
retry, silent root replacement or terminal-history deletion.

## Exact integers and validation scope

The browser requires lossless JSON parsing source context, `JSON.rawJSON`, Web
Locks and WebAuthn JSON support. It checks these capabilities before enabling
operations. Unsafe integer lexemes become BigInt and are serialized back as
exact JSON integers. Already rounded JavaScript numbers are rejected, as are
noninteger protocol fields. A successful 204 response is explicitly empty;
plain-text HTTP errors retain their failure status and message.

`tests/web` uses Node's built-in test runner and explicit HTTP/storage substitutes
for recovery/transport boundary regressions. The native suite exercises actual
HTTP authentication, SDK requests and static-module delivery separately. An
anonymous page-load check can verify module startup and rendering only. None of
these alone establishes the complete real-browser, live-policy, installed-client
enrollment path; that qualification remains open.
