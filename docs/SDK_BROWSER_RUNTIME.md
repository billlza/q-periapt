# Installed WASM browser execution

The current local alpha archive has actual desktop browser execution on macOS
ARM64 with **Chrome 153.0.8010.54** and stock **Firefox 156.0.1**, in both the
window and a dedicated module Worker. Both consume
the same installed `q-periapt-sdk-wasm` package that passes Node 24.0.0 and
26.3.0 consumption. The archive SHA-256 is
`6a75adb49acec798816be5731e9d4a98368ccd4942b444de13e658f5dba84b5c`;
its manifest SHA-256 is
`f39fea44ce7d0bbf09352049815a6a37abc4e296e527843e3c183a60e8808c2d`.
The package remains unpublished, and native ABI major remains **2**.

The [current browser checkpoint](../research/sdk-alpha1/evidence/20260927-wasm-public-view-browsers/manifest.json)
binds the archive, installed files, fixture sources, runtime versions and raw
protocol/log records after the prepared public-key storage change. Chrome runs through the existing Playwright acceptance
fixture in an isolated context. Firefox uses Mozilla's release browser and
geckodriver 0.37.1 with a fresh task profile, WebDriver and WebDriver BiDi. The
Firefox bundle is kept in the task's tool directory; its download checksum and
strict deep code-signature verification are recorded. No normal browsing profile
is used. TLS certificate exceptions are not enabled. Chrome's requested sandbox
option and actual automation arguments are retained; neither browser run is a
general assessment of browser isolation or operating-system security.

This capture completes ten Chrome cases, four deliberate failure controls, ten
Chrome cases after removing the interceptions, and ten Firefox cases. It verifies
the installed archive and fixture bytes before and after execution, and records
termination of the owned browsers, driver and loopback servers. The
[earlier worker checkpoint](../research/sdk-alpha1/evidence/20260926-wasm-dedicated-workers/manifest.json)
is retained with its original archive identity; its results are not relabeled.

## Behavior covered

Each browser runs the same five cases in each realm: ten cases against the
installed package, served only on loopback. The shared `browser-suite.mjs`
checks its actual global type, so a window result cannot satisfy a Worker case.
Successful cases use real WebCrypto randomness and the real WASM core.

| Case | Observed contract |
| --- | --- |
| Roundtrip | Signed-policy verification, numeric/size limits, key ownership and quotas, explicit expert transfer, five derivation purposes, close/revocation and shared initialization. |
| Missing entropy | Repeated key generation, encapsulation and expert import fail explicitly after the platform provider is removed; quotas are released. |
| Throwing entropy provider | Provider exceptions remain failures, with the same cleanup behavior. |
| Initialization failure | The actual WASM request returns HTTP 404; concurrent initializers share one rejected promise and do not silently retry. |
| Missing WebAssembly | Initialization is rejected deterministically. |

Both browsers record exactly one expected WASM fetch per case, its URL and final
HTTP status. All cases finish with explicit owner cleanup. Firefox records no
SDK-page warning or error. Chrome records only the expected HTTP 404 console
error in the initialization-failure case, with no uncaught page error. A timeout,
missing result, unexpected diagnostic or extra/missing WASM load is a failure.

## Dedicated Worker lifecycle

The fixture starts a fresh module Worker for each case and uses the same installed
web entry as the window. It closes/frees every retained SDK owner before sending
the result. The parent rejects startup/message errors and malformed results,
enforces a 15-second completion deadline, and terminates its owned Worker on
every outcome. Firefox's protocol records creation, the owning window realm,
destruction and no remaining worker realm after every case. Chrome records the
exact worker script URL; its subsequent checks also require no retained worker.

Four Chrome controls independently inject a startup exception, a malformed
completion message, an owner-cleanup exception after the real SDK assertions,
and a Worker that never sends a result. Each produces explicit failure and
leaves no Worker running; the absent-message case actually reaches the deadline.
All ten real SDK cases pass again after removing these test-only interceptions.

An SDK owner belongs to its WASM instance. Keep runtimes, keys and secrets inside
their Worker and exchange protocol bytes through messages; object cloning is not
an ownership-transfer API. Applications must bound their Worker count and queues.
Forceful Worker termination is not evidence that Rust destructors run or that
all memory has been erased. These checks cover explicit disposal before normal
completion, not interrupted-computation erasure, shared/service workers, Node
worker threads or cross-realm owner transfer.

## Diagnostics and limits

The [earlier window checkpoint](../research/sdk-alpha1/evidence/20260926-wasm-browser-engines/manifest.json)
found that the original fixture's empty `data:,` favicon caused a Firefox MIME-sniffer
error. Three fresh-profile controls loaded no SDK: no icon, the empty icon and
a valid SVG icon. Only the empty icon reproduced that error. The fixture now
uses the valid SVG; the full Firefox rerun has no favicon error and the Chrome
regression also passes.

Firefox's privileged-process logs still contain sandbox-extension denials,
storage-backend warnings, remote experiment configuration errors and occasional
actor/shutdown diagnostics. The same classes occur in the no-SDK controls,
including the valid-icon control. All logs are retained. Their OS/browser
integration impact is unresolved; the functional SDK result does not establish
that the environment is free of browser-security or sandbox problems. No sandbox
or system protection was disabled to remove those diagnostics.

The current capture repeats the storage-backend warning, sandbox-extension
denials and the `PrivateBrowsingUtils` shutdown error. All three are also present
in the sealed valid-icon, no-SDK baseline. That baseline has no WASM requests and
no SDK result. The comparison establishes that these diagnostics predate this
SDK change; it does not resolve their browser/OS security impact.

The first Worker collector run stopped because it interpreted Firefox's BiDi
realm `origin` as an origin-only string. The observed value was the complete
worker script URL, matching Mozilla's
[`getWorkerRealmInfo` implementation](https://searchfox.org/firefox-main/source/remote/webdriver-bidi/modules/root/script.sys.mjs).
That failed attempt is retained. The corrected collector checks the exact script
URL, owner realm and destruction, without changing any SDK assertion; it does
not present that driver field as evidence of web-origin isolation.

Safari 27's native driver was probed and rejected session creation because
**Allow remote automation** is disabled. Its setting remains unchanged, and no
Safari execution is claimed. Playwright WebKit is not a substitute for this
missing Safari result. Safari automation requires the user's permission to
enable the browser setting before the same fixture can run.

Other operating systems, mobile browsers, minimum browser versions, bundlers
and other Worker types remain unqualified. These checks also do not establish
constant-time behavior, performance/energy targets, independent security review
or formal 0.2.0 release readiness. See the
[release ledger](SDK_0_2_RELEASE_READINESS.md).
