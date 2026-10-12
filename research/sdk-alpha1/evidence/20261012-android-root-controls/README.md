# Android root noncommit and cancellation controls

This extends the [four-route root checkpoint](../20261012-android-root/README.md)
without changing the library AAR. The additional route passes **164 host calls
and 28 process cuts** under Debug/Release and fixed/recoverable trust, then
**82 ART calls and 14 cuts** on the same accepted phone. Owned installations and
ADB reverse mappings are removed. The single-phone acceptance scope remains met.

The new observations are:

- A modified noncommit signature is refused with 102 while preparation remains live.
- Explicitly retaining valid noncommit survives process exit as Closed. Exact replay
  remains Closed; trying to bind the old plan's freeze is refused with 112. Only a
  separately approved transition selects the distinct successor root.
- Idle cancellation rejects further controller calls with 302. Reopening preserves
  the original preparation; cancellation after successor activation leaves its
  acknowledged message query usable until the controller closes. The existing
  close check still observes successor revocation with 202.
- Original reports, acknowledgement and erasure, unknown activation, fresh traffic
  and exact retry retain the same checks as the preceding transition route.

`HOST_CAPTURE.zip` rereads 915 hashed members and four public trust/profile routes;
`ART_CAPTURE.zip` rereads 1,777 members and two routes. Seven state/linkage mutation
controls are rejected. The candidate integration reader also rereads all twenty
host routes across both checkpoints, exports exactly the bounded public inputs
it uses, and rejects incomplete execution receipts and child diagnostics. Native
execution authenticates signatures and the report MAC; public readback does not.

The APK adds qualification-only controls. Its AAR is byte-identical to the prior
root package (`84250d41fab17b8a3f0fccf51fc5c762e30af811e19c3bb776707a084679cb5c`).
This establishes idle cancellation semantics, not every possible concurrent
cancellation interleaving. Main-source/package-gate integration remains pending
while the earlier source-bound retirement qualifier is live. No release claim is made.
