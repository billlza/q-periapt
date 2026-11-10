# Android account-root replacement

This is the unpublished Android adapter for the existing account-root replacement
contract. It replaces an account root through an independent authority decision;
it is different from replacing a device generation under the same account root.
The SDK does not decide that a proposed new account belongs to the user.

## Inputs the application retains

Keep the original installation path, enrollment intent, account-authority registry,
expected account checkpoint, independently pinned witness, and independently
approved replacement plan. Prepare the successor through its own
`ContinuityConfiguration` and `ContinuityEnrollment`; its device key and journal
are created locally. Do not copy the original installation's private state into
the successor or recreate a missing registry as recovery.

`RootReplacementPlan`, `RootReplacementProposal`, `RootReplacementTransition` and
`RootReplacementAdoption` carry bounded public inputs. Constructing one of these
Java values does not authenticate it. The native operation verifies it against the
selected authority and pinned witness.

## Original approved target

1. Open the original registry and managed device. Call
   `authority.beginRootReplacement(device, scope, originalPlan)`. The registry
   becomes the replacement controller and the old device loses operational
   authority. Close the consumed device facade to release its table slot.
2. Obtain the independently signed freeze receipt and pass it to
   `authority.bindRootFreeze(receipt)`. Retain the exact returned proposal for the
   authority/witness operation. Do not invent a new operation after an uncertain
   response.
3. Retain the committed retirement receipt with
   `authority.retainRootRetirement(receipt)`. Open the original successor enrollment
   and call `authority.activateRootSuccessor(enrollment)`.
4. Keep the controller open for the lifetime of its successor device. Closing it
   revokes managed successor operations; reopening a registry does not revive an
   existing revoked child.

After a process restart, reopen the registry and call
`resumeRootReplacement(originalPath, originalIntent, scope, originalPlan)` before
resuming the original operation. An activation result of 218 is unknown: the
attempted controller/enrollment handles are consumed. Reopen from the original
retained inputs and reconcile; do not claim the activation failed to commit.

## Independently approved alternatives

For another approved target, retain the original noncommit receipt, separately
approved next plan and freeze receipt. Pass a `RootReplacementTransition` to
`transitionRoot`; resume it with `resumeRootTransition`. This also applies when the
original target was already bound but did not commit. The next target has its own
installation and account root.

If a separately approved competing replacement has already committed, retain its
proposal and retirement receipt together with the original plan's noncommit.
Pass a `RootReplacementAdoption` to `adoptRoot`; use `resumeRootAdoption` after
restart. A noncommit receipt alone does not authorize an arbitrary replacement.

## Original-device accounting and cleanup

Use the controller's retired inventory, report, acknowledgement and erasure
methods for the original device. Durably retain the complete host report before
obtaining its acknowledgement. After an interrupted report/journal/signer step,
reopen the original controller and continue with the same report and receipts.
`eraseRetiredSigner()` preserves this controller and successor; a standalone
`ContinuityRetiredEnrollment` has a different owner lifetime.

These methods do not make physical deletion a proof of cryptographic erasure,
turn historical `Committed` state into current traffic authorization, or make
remote application effects atomic. The application still commits and deduplicates
its business effects under the original message identity.
