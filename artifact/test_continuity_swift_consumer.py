"""Archive, scope and execution evidence must fail closed for the Swift adapter."""
import hashlib
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
from unittest import mock

import continuity_swift_consumer as swift


class SwiftConsumerTests(unittest.TestCase):
    def test_compiler_larger_than_consumer_budget_is_fully_hashed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            frontend = root / "swift-frontend"
            # Sparse real file crosses the old 256-MiB native-consumer bound.
            # It is hashed, never executed; the test does not allocate its size.
            with frontend.open("wb") as output:
                output.write(b"compiler identity fixture")
                output.seek(swift.c.MAX_BINARY)
                output.write(b"last compiler byte")
            frontend.chmod(0o755)
            alias = root / "swift"
            alias.symlink_to(frontend.name)
            command, identity = swift.compiler_command(str(alias))
            self.assertEqual(command, alias)
            self.assertEqual(identity["bytes"], frontend.stat().st_size)
            with frontend.open("rb") as stream:
                self.assertEqual(identity["sha256"], hashlib.file_digest(stream, "sha256").hexdigest())

    def test_compiler_cap_and_mutation_are_refused_without_buffering(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            frontend = root / "swift-frontend"
            with frontend.open("wb") as output:
                output.truncate(swift.MAX_COMPILER_BYTES + 1)
            frontend.chmod(0o755)
            alias = root / "swift"
            alias.symlink_to(frontend.name)
            with mock.patch.object(os, "read") as read, self.assertRaisesRegex(ValueError, "Swift compiler identity exceeds"):
                swift.compiler_command(str(alias))
            read.assert_not_called()
            frontend.write_bytes(b"stable compiler identity")
            original_read = os.read
            metadata = frontend.stat()
            changed = False

            def mutate_after_read(descriptor, count):
                nonlocal changed
                data = original_read(descriptor, count)
                if data and not changed:
                    changed = True
                    os.utime(frontend, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000))
                return data

            with mock.patch.object(os, "read", side_effect=mutate_after_read), self.assertRaisesRegex(ValueError, "changed while it was read"):
                swift.compiler_command(str(alias))
            self.assertTrue(changed)

    def test_swift_dispatch_name_is_preserved_while_target_bytes_are_hashed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            frontend = root / "swift-frontend"
            frontend.write_bytes(b"tool identity fixture")
            frontend.chmod(0o755)
            alias = root / "swift"
            alias.symlink_to(frontend.name)
            command, identity = swift.compiler_command(str(alias))
            self.assertEqual(command, alias)
            self.assertEqual(identity["path"], str(frontend))
            self.assertEqual(identity["sha256"], hashlib.sha256(frontend.read_bytes()).hexdigest())
            with self.assertRaisesRegex(ValueError, "command differs"):
                swift.compiler_command(str(frontend))

    def test_archive_bytes_must_match_before_any_installation(self):
        data = swift.archive({"Package.swift": b"manifest", "Sources/Client.swift": b"source"})
        expected = {"Package.swift": hashlib.sha256(b"manifest").hexdigest(),
                    "Sources/Client.swift": hashlib.sha256(b"source").hexdigest()}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            swift.unpack(data, expected, root / "good")
            self.assertEqual((root / "good/Sources/Client.swift").read_bytes(), b"source")
            with self.assertRaisesRegex(ValueError, "destination"):
                swift.unpack(data, expected, root / "good")
            changed = dict(expected, **{"Sources/Client.swift": "0" * 64})
            with self.assertRaisesRegex(ValueError, "hash"):
                swift.unpack(data, changed, root / "bad")
            self.assertFalse((root / "bad").exists())

    def test_traversal_and_symlink_entries_are_refused_before_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            for index, (name, mode) in enumerate((("../escape", stat.S_IFREG), ("lib", stat.S_IFLNK))):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as zipped:
                    item = zipfile.ZipInfo(name)
                    item.external_attr = (mode | 0o644) << 16
                    zipped.writestr(item, b"target")
                output = Path(folder) / str(index)
                with self.assertRaisesRegex(ValueError, "canonical regular"):
                    swift.unpack(buffer.getvalue(), {name: hashlib.sha256(b"target").hexdigest()}, output)
                self.assertFalse(output.exists())

    def test_passing_summary_without_each_swift_test_is_refused(self):
        with self.assertRaisesRegex(ValueError, "all execute"):
            swift.verify_tests(b"Executed 32 tests, with 0 failures", b"")
        names = (("OwnerTests", "testARCRetiresPendingSlotsAndClosedAliases"),
                 ("OwnerTests", "testDiagnosticRejectsInconsistentAndInvalidUTF8"),
                 ("OwnerTests", "testIDsAndTextsRejectAmbiguousInput"),
                 ("ServerTests", "testCallbackCopiesBorrowedRegions"),
                 ("ServerTests", "testCallbackFailureAndForeignBoundsCannotBecomeConsumption"),
                 ("ServerTests", "testServedRecordRejectsUnknownKindsAndInconsistentBootstrap"),
                 ("RecoveryTests", "testRecoverySharesRegistryAndRetainsCancelledClosedAuthority"),
                 ("RecoveryTests", "testClosureDecodingPreservesCountersAndRejectsUnknownStates"),
                 ("RecoveryTests", "testClosureStatusKeepsReportIdentityAndRejectsMalformedOpen"),
                 ("AccountRecoveryTests", "testCompleteAccountMetadataPreservesFullWidthAndRejectsMalformedPresence"),
                 ("AccountRecoveryTests", "testAccountCleanupStatusRejectsNarrowingAndKeepsExactReport"),
                 ("AccountRecoveryTests", "testAccountCleanupCannotAcquireAuthorityFromPendingOrClosedOwner"),
                 ("AccountRecoveryTests", "testReconciliationKeepsEveryOutcomeAndRejectsPartialOrNoncanonicalFrames"),
                 ("DeviceTests", "testPreparedDeviceCapacityCancellationAndNoPrematurePeerAuthority"),
                 ("DeviceTests", "testAggregateStatusRequiresTheExactReportShapeAndPreservesUnknownStates"),
                 ("DeviceTests", "testAccountDeliveryRejectsMisboundOutputAndDistinguishesRetainedOutcomes"),
                 ("SetupTests", "testPendingSetupSharesCapacityAndCannotActivateAfterCancellation"),
                 ("SetupTests", "testInstallationStatusRejectsUnknownPhaseAndZeroJournal"),
                 ("SetupTests", "testOriginalGenesisRejectsMisbindingAndUnexpectedWitnessMetadata"),
                 ("EnrollmentTests", "testNativeEnrollmentLayoutsMatchHeader"),
                 ("EnrollmentTests", "testSixPhasesRejectImpossibleIdentityAndCheckpointCombinations"),
                 ("EnrollmentTests", "testRequestRejectsTruncationAndUnexpectedTail"),
                 ("EnrollmentTests", "testApprovedValuesOwnBytesAndPreserveUnsignedCounters"),
                 ("EnrollmentTests", "testPreparationCopiesIntentAndNativeRequestSurvivesFailedActivation"),
                 ("EnrollmentTests", "testPendingRegistrationSharesQuotaAndPreservesCloseAfterRefusal"),
                 ("CredentialRenewalTests", "testRenewalStatusPreservesHistoricalBindingAndRejectsMalformedCombinations"),
                 ("CredentialRenewalTests", "testWitnessProposalOwnsCanonicalBytesAndRejectsOverflowOrContradictoryHeads"),
                 ("CredentialRenewalTests", "testCancellationOwnsTargetFreeBytesAndRejectsProposalOrInvalidHead"),
                 ("CredentialRenewalTests", "testOriginalRenewalIdentitiesOwnBytesAndRejectZeroOrWrongWidths"),
                 ("PolicyContinuationTests", "testIndependentPolicyDocumentOwnsInputAndMatchesNativeLayout"),
                 ("PolicyContinuationTests", "testExtendedProposalAndCancellationPreserveGAndTWithExplicitTransactionMode"),
                 ("PolicyContinuationTests", "testExtendedMetadataRejectsInvalidModeTVersionAndWidth"),
                 ("PolicyContinuationTests", "testVariableNativeRecordsCheckPayloadTailAndExcludeABIPadding"),
                 ("PolicyRenewalTests", "testNativeLayoutsAndOffsetsAreExact"),
                 ("PolicyRenewalTests", "testRetainedRequestRoundTripOwnsAllBytesAndPreservesUnsignedCounters"),
                 ("PolicyRenewalTests", "testScopeRejectsContradictoryPredecessorAndNoncanonicalNativeOption"),
                 ("PolicyRenewalTests", "testRequestRejectsDirtyTailEmptyFieldsAndImpossibleOriginalHead"),
                 ("PolicyRenewalTests", "testAllStatusStatesRemainDistinctIncludingBothAbandonmentReasons"),
                 ("PolicyRenewalTests", "testMalformedStatusesCannotBecomeCommittedOrNoCommit"),
                 ("RosterResolutionTests", "testABIHasExplicitReservedFieldAndExactOffsets"),
                 ("RosterResolutionTests", "testAllFourOutcomesAndUnsignedUnknownRemainDistinct"),
                 ("RosterResolutionTests", "testMalformedOrContradictoryResultsNeverBecomeNoCommit"),
                 ("RosterResolutionTests", "testResolvedEnrollmentPreservesOriginalPairAndRejectsUnknownPhase"),
                 ("RosterRefreshTests", "testRetainedRosterProposalOwnsExactScopeAndRejectsOtherDomains"),
                 ("RosterRefreshTests", "testRosterPreparationChecksCanonicalAbsenceAndABI"),
                 ("RosterRefreshTests", "testRosterProgressPreservesAllSixStatesAndChecksProposalScope"),
                 ("RosterRefreshTests", "testRosterCallsRespectPreparedCancelledAndClosedOwners"),
                 ("RosterRefreshTests", "testPeerRosterAdmissionRespectsBoundsAndOwnerLifetime"),
                 ("IndependentPolicyTests", "testIndependentDescriptorPreservesAllBytesAndRejectsOtherDomains"),
                 ("IndependentPolicyTests", "testPreparationDistinguishesCanonicalAbsenceAndRejectsDirtyFlags"),
                 ("IndependentPolicyTests", "testProgressKeepsEveryTerminalAndRetirementStateDistinct"),
                 ("IndependentPolicyTests", "testWitnessCallsRespectPreparedCancelledAndClosedOwnerBoundaries"),
                 ("PublicationTests", "testPublicationLayoutsAndPlanOwnCompleteOriginalInputs"),
                 ("PublicationTests", "testPublicationStatesRejectDirtyAbsenceAndUnknownCompletion"),
                 ("PublicationTests", "testPublicationArtifactOwnsCompleteBytesAndRejectsTruncationSubstitutionAndTail"),
                 ("PublicationTests", "testPreparedDeviceCannotPublishOrAcquireAuthorityAndClosedOwnerStaysClosed"),
                 ("RetirementTests", "testRetirementLayoutsMatchTheNativeContract"),
                 ("RetirementTests", "testRetirementAuthorityOwnsBoundedInputsWithoutGrantingTrust"),
                 ("RetirementTests", "testRetirementProposalRejectsDirtyAbsenceAndPreservesOriginalIdentity"),
                 ("RetirementTests", "testCompleteRetirementReportKeepsBytesSeparateFromItsKeyedID"))
        names += (("PeerConfigurationTests", "testCallerMutationCannotChangeStoredOrNativePeerInputs"),
                  ("PeerConfigurationTests", "testWidthsAndBoundsPrecedeNativeAdmission"))
        output = ("\n".join(f"Test Case '-[QPeriaptContinuityTests.{owner} {name}]' passed" for owner, name in names)
                  + "\nExecuted 62 tests, with 0 failures").encode()
        swift.verify_tests(output, b"")
        with self.assertRaisesRegex(ValueError, "all execute"):
            swift.verify_tests(output + output, b"")
        with self.assertRaisesRegex(ValueError, "all execute"):
            swift.verify_tests(b"\n".join(line for line in output.splitlines() if b"EnrollmentTests" not in line), b"")
        with self.assertRaisesRegex(ValueError, "all execute"):
            swift.verify_tests(b"\n".join(line for line in output.splitlines() if b"PolicyContinuationTests" not in line), b"")
        with self.assertRaisesRegex(ValueError, "all execute"):
            swift.verify_tests(b"\n".join(line for line in output.splitlines() if b"RetirementTests" not in line), b"")

    def test_foreign_library_and_missing_installed_rpath_are_refused(self):
        dependencies = "client:\n\t@rpath/" + swift.LIBRARY + " (compatibility version 0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 0)\n"
        path = Path("/installed/native/lib")
        loader = "cmd LC_RPATH\ncmdsize 128\npath /installed/native/lib (offset 12)"
        self.assertEqual(swift.verify_linkage(dependencies, loader, path), [str(path)])
        with self.assertRaisesRegex(ValueError, "search path"):
            swift.verify_linkage(dependencies, loader.replace("/installed", "/build"), path)
        with self.assertRaisesRegex(ValueError, "unqualified"):
            swift.verify_linkage(dependencies + "\t/tmp/unqualified.dylib (compatibility version 0)\n", loader, path)


if __name__ == "__main__":
    unittest.main()
