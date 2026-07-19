import OSLog

public enum RecoveryDiagnosticOperation: String, Equatable, Sendable {
  case app
  case backupPicker = "backup_picker"
  case preflight
  case recovery
  case validation
  case outputAccess = "output_access"
}

public enum RecoveryDiagnosticMilestone: String, Equatable, Sendable {
  case appLaunched = "app_launched"
  case pickerPresented = "picker_presented"
  case pickerCancelled = "picker_cancelled"
  case backupAccepted = "backup_accepted"
  case privateStoragePrepared = "private_storage_prepared"
  case requested
  case started
  case completed
  case cancellationRequested = "cancellation_requested"
  case cancelled
}

public enum RecoveryDiagnosticFailure: String, Equatable, Sendable {
  case invalidInput = "invalid_input"
  case backupUnencrypted = "backup_unencrypted"
  case backupUnfinished = "backup_unfinished"
  case appDataMissing = "app_data_missing"
  case sourceChanged = "source_changed"
  case unsupportedSchema = "unsupported_schema"
  case insufficientSpace = "insufficient_space"
  case outputExists = "output_exists"
  case unsafePath = "unsafe_path"
  case destinationUnencrypted = "destination_unencrypted"
  case backupPasswordRejected = "backup_password_rejected"
  case preflightCancelled = "preflight_cancelled"
  case cancelled
  case partialExtraction = "partial_extraction"
  case recoveryFailed = "recovery_failed"
  case localHelperError = "local_helper_error"
  case outputValidationFailed = "output_validation_failed"
  case validationInvalidSummary = "validation_invalid_summary"
  case validationMissingArtifact = "validation_missing_artifact"
  case validationUnsafeArtifact = "validation_unsafe_artifact"
  case validationInsecurePermissions = "validation_insecure_permissions"
  case validationUnreadableMarker = "validation_unreadable_marker"
  case validationIncompleteOutput = "validation_incomplete_output"
  case validationArtifactIntegrity = "validation_artifact_integrity"
  case helperUnavailable = "helper_unavailable"
  case helperBusy = "helper_busy"
  case invalidFrame = "invalid_frame"
  case helperLaunchFailed = "helper_launch_failed"
  case helperCommunicationFailed = "helper_communication_failed"
  case invalidEventStream = "invalid_event_stream"
  case incompatibleProtocol = "incompatible_protocol"
  case helperExitedUnexpectedly = "helper_exited_unexpectedly"
  case destinationChanged = "destination_changed"
  case pickerInvalidBackup = "picker_invalid_backup"
  case pickerMultipleBackups = "picker_multiple_backups"
  case pickerInvalidDirectory = "picker_invalid_directory"
  case pickerUnreadableDirectory = "picker_unreadable_directory"
  case outputUnavailable = "output_unavailable"
  case privateStorageUnavailable = "private_storage_unavailable"
  case unrecognizedFailure = "unrecognized_failure"

  public init(recoveryFailureCode: String) {
    switch recoveryFailureCode {
    case "invalid_input":
      self = .invalidInput
    case "backup_unencrypted":
      self = .backupUnencrypted
    case "backup_unfinished":
      self = .backupUnfinished
    case "app_data_missing":
      self = .appDataMissing
    case "source_changed":
      self = .sourceChanged
    case "unsupported_schema":
      self = .unsupportedSchema
    case "insufficient_space":
      self = .insufficientSpace
    case "output_exists":
      self = .outputExists
    case "unsafe_path":
      self = .unsafePath
    case "destination_unencrypted":
      self = .destinationUnencrypted
    case "backup_password_rejected":
      self = .backupPasswordRejected
    case "preflight_cancelled":
      self = .preflightCancelled
    case "cancelled":
      self = .cancelled
    case "partial_extraction":
      self = .partialExtraction
    case "recovery_failed":
      self = .recoveryFailed
    case "local_helper_error":
      self = .localHelperError
    case "output_validation_failed":
      self = .outputValidationFailed
    default:
      self = .unrecognizedFailure
    }
  }

  public init(error: Error) {
    if let validationError = error as? RecoveryOutputValidationError {
      switch validationError {
      case .invalidSummary:
        self = .validationInvalidSummary
      case .missingArtifact:
        self = .validationMissingArtifact
      case .unsafeArtifact:
        self = .validationUnsafeArtifact
      case .insecurePermissions:
        self = .validationInsecurePermissions
      case .unreadableCompletionMarker:
        self = .validationUnreadableMarker
      case .incompleteOutput:
        self = .validationIncompleteOutput
      case .artifactIntegrityFailure:
        self = .validationArtifactIntegrity
      }
      return
    }
    if let destinationError = error as? EncryptedDestinationValidationError {
      switch destinationError {
      case .encryptionNotConfirmed:
        self = .destinationUnencrypted
      case .localStorageNotConfirmed, .cloudOrSharedLocation, .identityNotConfirmed:
        self = .unsafePath
      }
      return
    }
    if let helperError = error as? HelperClientError {
      switch helperError {
      case .helperUnavailable:
        self = .helperUnavailable
      case .helperBusy:
        self = .helperBusy
      case .invalidFrame:
        self = .invalidFrame
      case .launchFailed:
        self = .helperLaunchFailed
      case .communicationFailed:
        self = .helperCommunicationFailed
      case .invalidEventStream:
        self = .invalidEventStream
      case .incompatibleProtocol:
        self = .incompatibleProtocol
      case .helperExitedUnexpectedly:
        self = .helperExitedUnexpectedly
      case .destinationChanged:
        self = .destinationChanged
      }
      return
    }
    self = .unrecognizedFailure
  }
}

extension RecoveryAction {
  var diagnosticOperation: RecoveryDiagnosticOperation {
    switch self {
    case .preflight:
      .preflight
    case .recover:
      .recovery
    }
  }
}

public enum RecoveryDiagnosticEvent: Equatable, Sendable {
  case milestone(RecoveryDiagnosticOperation, RecoveryDiagnosticMilestone)
  case failure(RecoveryDiagnosticOperation, RecoveryDiagnosticFailure)
}

@MainActor
public protocol RecoveryDiagnosticsSink: AnyObject {
  func record(_ event: RecoveryDiagnosticEvent)
}

@MainActor
public final class UnifiedRecoveryDiagnostics: RecoveryDiagnosticsSink {
  private let logger: Logger

  public init(
    subsystem: String = "com.amirbrooks.tvtime-backup-extractor",
    category: String = "RecoveryDiagnostics"
  ) {
    logger = Logger(subsystem: subsystem, category: category)
  }

  public func record(_ event: RecoveryDiagnosticEvent) {
    switch event {
    case .milestone(let operation, let milestone):
      logger.info(
        "event=\(milestone.rawValue, privacy: .public) operation=\(operation.rawValue, privacy: .public)"
      )
    case .failure(let operation, let failure):
      logger.error(
        "event=failed operation=\(operation.rawValue, privacy: .public) reason=\(failure.rawValue, privacy: .public)"
      )
    }
  }
}
