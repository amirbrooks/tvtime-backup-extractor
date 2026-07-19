import Foundation
import Testing

@testable import TVTimeRecoveryCore

@Suite("Privacy-safe recovery diagnostics")
struct RecoveryDiagnosticsTests {
  @Test
  func testFailureCodesAreAnExactAllowList() {
    expectEqual(
      RecoveryDiagnosticFailure(recoveryFailureCode: "backup_unencrypted"),
      .backupUnencrypted
    )
    expectEqual(
      RecoveryDiagnosticFailure(recoveryFailureCode: "local_helper_error"),
      .localHelperError
    )
    for unsafe in [
      "/Users/example/Library/Application Support/MobileSync/Backup/private",
      "password=do-not-log",
      "A Show Title",
      "backup_unencrypted\nprivate-data",
      String(repeating: "x", count: 10_000),
    ] {
      expectEqual(
        RecoveryDiagnosticFailure(recoveryFailureCode: unsafe),
        .unrecognizedFailure
      )
    }
  }

  @Test
  func testTypedLocalErrorsMapWithoutTheirDescriptions() {
    expectEqual(
      RecoveryDiagnosticFailure(error: HelperClientError.helperUnavailable),
      .helperUnavailable
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: HelperClientError.communicationFailed),
      .helperCommunicationFailed
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: EncryptedDestinationValidationError.identityNotConfirmed),
      .unsafePath
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: SensitiveSyntheticError()),
      .unrecognizedFailure
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: RecoveryOutputValidationError.invalidSummary),
      .validationInvalidSummary
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: RecoveryOutputValidationError.missingArtifact),
      .validationMissingArtifact
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: RecoveryOutputValidationError.unsafeArtifact),
      .validationUnsafeArtifact
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: RecoveryOutputValidationError.insecurePermissions),
      .validationInsecurePermissions
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: RecoveryOutputValidationError.unreadableCompletionMarker),
      .validationUnreadableMarker
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: RecoveryOutputValidationError.incompleteOutput),
      .validationIncompleteOutput
    )
    expectEqual(
      RecoveryDiagnosticFailure(error: RecoveryOutputValidationError.artifactIntegrityFailure),
      .validationArtifactIntegrity
    )
  }

  @Test
  func testEveryPublishedValueIsBoundedProtocolText() {
    let values =
      RecoveryDiagnosticOperation.allDiagnosticRawValues
      + RecoveryDiagnosticMilestone.allDiagnosticRawValues
      + RecoveryDiagnosticFailure.allDiagnosticRawValues
    for value in values {
      expectTrue(value.count <= 64, value)
      expectTrue(
        value.unicodeScalars.allSatisfy { scalar in
          scalar.isASCII
            && ((scalar.value >= 97 && scalar.value <= 122)
              || (scalar.value >= 48 && scalar.value <= 57)
              || scalar.value == 95)
        },
        value
      )
    }
  }
}

private struct SensitiveSyntheticError: LocalizedError {
  var errorDescription: String? {
    "Password do-not-log failed at /Users/example/private-backup for A Show Title"
  }
}

extension RecoveryDiagnosticOperation {
  fileprivate static let allDiagnosticRawValues = [
    Self.app, .backupPicker, .preflight, .recovery, .validation, .outputAccess,
  ].map(\.rawValue)
}

extension RecoveryDiagnosticMilestone {
  fileprivate static let allDiagnosticRawValues = [
    Self.appLaunched, .pickerPresented, .pickerCancelled, .backupAccepted,
    .privateStoragePrepared, .requested, .started, .completed, .cancellationRequested,
    .cancelled,
  ].map(\.rawValue)
}

extension RecoveryDiagnosticFailure {
  fileprivate static let allDiagnosticRawValues = [
    Self.invalidInput, .backupUnencrypted, .backupUnfinished, .appDataMissing, .sourceChanged,
    .unsupportedSchema, .insufficientSpace, .outputExists, .unsafePath,
    .destinationUnencrypted, .backupPasswordRejected, .preflightCancelled, .cancelled,
    .partialExtraction, .recoveryFailed, .localHelperError, .outputValidationFailed,
    .validationInvalidSummary, .validationMissingArtifact, .validationUnsafeArtifact,
    .validationInsecurePermissions, .validationUnreadableMarker, .validationIncompleteOutput,
    .validationArtifactIntegrity,
    .helperUnavailable, .helperBusy, .invalidFrame, .helperLaunchFailed,
    .helperCommunicationFailed, .invalidEventStream, .incompatibleProtocol,
    .helperExitedUnexpectedly, .destinationChanged, .pickerInvalidBackup,
    .pickerMultipleBackups, .pickerInvalidDirectory, .pickerUnreadableDirectory,
    .outputUnavailable, .privateStorageUnavailable, .unrecognizedFailure,
  ].map(\.rawValue)
}
