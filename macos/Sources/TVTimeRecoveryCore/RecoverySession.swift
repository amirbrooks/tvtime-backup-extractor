import Foundation
import Observation

public enum RecoveryRetryRoute: Equatable, Sendable {
  case chooseBackup
  case chooseDestination
  case retryPasswordWithFreshOutput
  case retryWithFreshOutput
  case retrySamePreflight
  case startOverOnly
}

public struct RecoveryFailureRecoveryPlan: Equatable, Sendable {
  public let route: RecoveryRetryRoute
  public let title: String
  public let primaryActionTitle: String?
  public let guidance: String
  public let isCancellation: Bool
}

extension RecoveryFailure {
  public var userVisibleMessage: String? {
    guard hasKnownRecoveryPresentation else {
      return nil
    }
    let candidate = message.trimmingCharacters(in: .whitespacesAndNewlines)
    guard
      !candidate.isEmpty,
      candidate.count <= 500,
      !candidate.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
      !candidate.contains("/"),
      !candidate.contains("\\"),
      !candidate.contains("~"),
      !candidate.contains("@")
    else {
      return nil
    }
    let lowercase = candidate.lowercased()
    let sensitiveMarkers = [
      "password", "passcode", "secret", "token", "api key", "api_key",
    ]
    guard
      !lowercase.localizedCaseInsensitiveContains("file:"),
      !sensitiveMarkers.contains(where: lowercase.contains)
    else {
      return nil
    }
    return candidate
  }

  public var userVisibleReferenceCode: String {
    guard
      !code.isEmpty,
      code.count <= 64,
      code.unicodeScalars.allSatisfy({ scalar in
        scalar.isASCII
          && ((scalar.value >= 97 && scalar.value <= 122)
            || (scalar.value >= 48 && scalar.value <= 57)
            || scalar.value == 95)
      })
    else {
      return "unrecognized_failure"
    }
    return code
  }

  public var recoveryPlan: RecoveryFailureRecoveryPlan {
    switch code {
    case "invalid_input":
      RecoveryFailureRecoveryPlan(
        route: .startOverOnly,
        title: "Selections failed a safety check",
        primaryActionTitle: nil,
        guidance:
          "Start over and choose regular local folders that do not overlap the backup, cloud sync, shared folders, or Git repositories.",
        isCancellation: false
      )
    case "backup_unencrypted":
      RecoveryFailureRecoveryPlan(
        route: .chooseBackup,
        title: "Encrypted backup required",
        primaryActionTitle: "Choose Another Backup",
        guidance: "Choose a completed local backup with encryption enabled, then check it again.",
        isCancellation: false
      )
    case "backup_unfinished":
      RecoveryFailureRecoveryPlan(
        route: .chooseBackup,
        title: "Backup is not finished",
        primaryActionTitle: "Review Backup",
        guidance:
          "Let the device backup finish in Finder, Apple Devices, or iTunes, then choose the completed backup.",
        isCancellation: false
      )
    case "app_data_missing":
      RecoveryFailureRecoveryPlan(
        route: .chooseBackup,
        title: "TV Time data was not found",
        primaryActionTitle: "Choose Another Backup",
        guidance:
          "Choose a backup from a device and date when TV Time was installed and its data was present.",
        isCancellation: false
      )
    case "source_changed":
      RecoveryFailureRecoveryPlan(
        route: .chooseBackup,
        title: "Backup changed during recovery",
        primaryActionTitle: "Review Backup",
        guidance:
          "Make sure the backup is complete and no backup or sync is running, then choose it again.",
        isCancellation: false
      )
    case "unsupported_schema":
      RecoveryFailureRecoveryPlan(
        route: .chooseBackup,
        title: "This TV Time data is not supported",
        primaryActionTitle: "Choose Another Backup",
        guidance:
          "Choose another completed backup. This app will not guess at an unsupported data layout.",
        isCancellation: false
      )
    case "insufficient_space":
      RecoveryFailureRecoveryPlan(
        route: .startOverOnly,
        title: "More local space is needed",
        primaryActionTitle: nil,
        guidance:
          "Free space on this Mac, then start over. Existing incomplete output is preserved.",
        isCancellation: false
      )
    case "output_exists":
      RecoveryFailureRecoveryPlan(
        route: .startOverOnly,
        title: "A fresh output folder is required",
        primaryActionTitle: nil,
        guidance:
          "Start over so the app can prepare a fresh private local recovery folder. Existing files will not be overwritten.",
        isCancellation: false
      )
    case "unsafe_path":
      RecoveryFailureRecoveryPlan(
        route: .startOverOnly,
        title: "Private storage is not safe",
        primaryActionTitle: nil,
        guidance:
          "Start over so the app can recheck its private local storage. No recovered plaintext was written to an unsafe path.",
        isCancellation: false
      )
    case "destination_unencrypted":
      RecoveryFailureRecoveryPlan(
        route: .startOverOnly,
        title: "Private storage could not be verified",
        primaryActionTitle: nil,
        guidance:
          "Start over so the app can prepare and verify a fresh private local recovery folder.",
        isCancellation: false
      )
    case "backup_password_rejected":
      RecoveryFailureRecoveryPlan(
        route: .retryPasswordWithFreshOutput,
        title: "Backup password was not accepted",
        primaryActionTitle: "Recheck and Enter Password",
        guidance:
          "A fresh output folder will be prepared and the backup checked again before you enter the encryption password.",
        isCancellation: false
      )
    case "preflight_cancelled":
      RecoveryFailureRecoveryPlan(
        route: .retrySamePreflight,
        title: "Backup check cancelled",
        primaryActionTitle: "Check Again",
        guidance:
          "The same backup and private storage will be checked again. No recovery output will be created or changed.",
        isCancellation: true
      )
    case "cancelled":
      freshOutputPlan(
        title: "Recovery cancelled",
        guidance:
          "Incomplete output is preserved. A fresh output folder will be used for a new read-only backup check.",
        isCancellation: true
      )
    case "partial_extraction":
      freshOutputPlan(
        title: "Some selected files could not be recovered",
        guidance:
          "Preserve the incomplete output. A fresh output folder and a new read-only backup check are required before another attempt."
      )
    case "recovery_failed", "local_helper_error":
      freshOutputPlan(
        title: "Recovery stopped safely",
        guidance:
          "Preserve the incomplete output. A fresh output folder and a new read-only backup check are required before another attempt."
      )
    case "output_validation_failed":
      freshOutputPlan(
        title: "Recovered output could not be verified",
        guidance:
          "Preserve this output for review. A fresh output folder and a new read-only backup check are required before another attempt."
      )
    default:
      RecoveryFailureRecoveryPlan(
        route: .startOverOnly,
        title: "Recovery stopped safely",
        primaryActionTitle: nil,
        guidance:
          "Start over to choose the backup and prepare private storage again. Existing incomplete output is preserved.",
        isCancellation: false
      )
    }
  }

  private var hasKnownRecoveryPresentation: Bool {
    switch code {
    case "invalid_input", "backup_unencrypted", "backup_unfinished", "app_data_missing",
      "source_changed", "unsupported_schema", "insufficient_space", "output_exists",
      "unsafe_path", "destination_unencrypted", "backup_password_rejected",
      "preflight_cancelled", "cancelled", "partial_extraction", "recovery_failed",
      "local_helper_error", "output_validation_failed":
      true
    default:
      false
    }
  }

  private func freshOutputPlan(
    title: String,
    guidance: String,
    isCancellation: Bool = false
  ) -> RecoveryFailureRecoveryPlan {
    RecoveryFailureRecoveryPlan(
      route: .retryWithFreshOutput,
      title: title,
      primaryActionTitle: "Recheck with Fresh Output",
      guidance: guidance,
      isCancellation: isCancellation
    )
  }
}

@MainActor
@Observable
public final class RecoverySession {
  public private(set) var phase: RecoveryPhase = .chooseBackup
  public private(set) var backupDirectory: URL?
  public private(set) var destinationParent: URL?
  public private(set) var outputDirectory: URL?
  public private(set) var preflightSummary: PreflightSummary?
  public private(set) var pendingCancellationPrompt: RecoveryCancellationPrompt?

  @ObservationIgnored
  private let helperClient: any RecoveryHelperClient

  @ObservationIgnored
  private let diagnostics: any RecoveryDiagnosticsSink

  @ObservationIgnored
  private let destinationEncryptionValidator: (URL) throws -> DestinationDirectoryIdentity

  @ObservationIgnored
  private let recoveryOutputValidator: @Sendable (RecoverySummary, URL) throws -> Void

  @ObservationIgnored
  private var operationTask: Task<Void, Never>?

  @ObservationIgnored
  private var validationTask: Task<Void, Error>?

  @ObservationIgnored
  private var retainedDestinationLease: SecurityScopedResourceLease?

  @ObservationIgnored
  private var cancellationDecisionHandlers: [@MainActor (Bool) -> Void] = []

  @ObservationIgnored
  private var cancellationSignalSent = false

  @ObservationIgnored
  private var activeAction: RecoveryAction?

  @ObservationIgnored
  private var destinationParentIdentity: DestinationDirectoryIdentity?

  @ObservationIgnored
  private var backupReceipt: BackupReceipt?

  public init(
    helperClient: any RecoveryHelperClient,
    diagnostics: any RecoveryDiagnosticsSink = UnifiedRecoveryDiagnostics(),
    destinationEncryptionValidator: @escaping (URL) throws -> DestinationDirectoryIdentity = {
      try EncryptedDestinationValidator.requirePrivateEncryptedLocalDestination(at: $0)
    }
  ) {
    self.helperClient = helperClient
    self.diagnostics = diagnostics
    self.destinationEncryptionValidator = destinationEncryptionValidator
    recoveryOutputValidator = {
      try RecoveryOutputValidator.validate($0, beneath: $1)
    }
  }

  init(
    helperClient: any RecoveryHelperClient,
    diagnostics: any RecoveryDiagnosticsSink = UnifiedRecoveryDiagnostics(),
    destinationEncryptionValidator: @escaping (URL) throws -> DestinationDirectoryIdentity,
    recoveryOutputValidator: @escaping @Sendable (RecoverySummary, URL) throws -> Void
  ) {
    self.helperClient = helperClient
    self.diagnostics = diagnostics
    self.destinationEncryptionValidator = destinationEncryptionValidator
    self.recoveryOutputValidator = recoveryOutputValidator
  }

  public func selectBackup(_ url: URL) {
    guard !phase.isBusy else {
      return
    }
    retainedDestinationLease?.stop()
    retainedDestinationLease = nil
    backupDirectory = url.standardizedFileURL
    destinationParent = nil
    destinationParentIdentity = nil
    outputDirectory = nil
    preflightSummary = nil
    backupReceipt = nil
    phase = .chooseDestination
  }

  public func selectBackup(_ url: URL, appManagedDestinationParent: URL) {
    guard !phase.isBusy else {
      return
    }
    retainedDestinationLease?.stop()
    retainedDestinationLease = nil
    backupDirectory = url.standardizedFileURL
    destinationParent = appManagedDestinationParent.standardizedFileURL
    destinationParentIdentity = nil
    outputDirectory = freshOutputDirectory(in: appManagedDestinationParent)
    preflightSummary = nil
    backupReceipt = nil
    diagnostics.record(.milestone(.backupPicker, .backupAccepted))
    diagnostics.record(.milestone(.preflight, .requested))
    startPreflight()
  }

  public func selectDestinationParent(_ url: URL) {
    guard !phase.isBusy, backupDirectory != nil else {
      return
    }
    destinationParent = url.standardizedFileURL
    destinationParentIdentity = nil
    outputDirectory = freshOutputDirectory(in: url)
    preflightSummary = nil
    backupReceipt = nil
    startPreflight()
  }

  public func startRecovery(password: String, acknowledgeSensitiveOutput: Bool) {
    guard
      case .confirm = phase,
      acknowledgeSensitiveOutput,
      !password.isEmpty,
      let backupDirectory,
      let destinationParent,
      let outputDirectory,
      let expectedDestinationIdentity = destinationParentIdentity,
      let backupReceipt
    else {
      return
    }

    let sourceLease = SecurityScopedResourceLease(url: backupDirectory)
    let destinationLease = SecurityScopedResourceLease(url: destinationParent)
    var secret = Data(password.utf8)
    defer {
      if !secret.isEmpty {
        secret.resetBytes(in: 0..<secret.count)
      }
    }

    do {
      diagnostics.record(.milestone(.recovery, .requested))
      let currentDestinationIdentity = try destinationEncryptionValidator(destinationParent)
      guard currentDestinationIdentity == expectedDestinationIdentity else {
        throw EncryptedDestinationValidationError.identityNotConfirmed
      }
      let request = RecoveryRequest(
        action: .recover,
        backupDirectory: backupDirectory,
        outputDirectory: outputDirectory,
        destinationParentIdentity: currentDestinationIdentity,
        acknowledgeSensitiveOutput: true,
        backupReceipt: backupReceipt
      )
      prepareForOperation()
      activeAction = .recover
      let stream = try helperClient.events(for: request, secret: secret)
      phase = .running(
        RecoveryProgress(
          stage: "preflight",
          kind: "started",
          message: "Starting private recovery..."
        )
      )
      diagnostics.record(.milestone(.recovery, .started))
      consume(
        stream,
        sourceLease: sourceLease,
        destinationLease: destinationLease,
        retainDestinationOnSuccess: true
      )
    } catch {
      activeAction = nil
      sourceLease.stop()
      destinationLease.stop()
      diagnostics.record(.failure(.recovery, RecoveryDiagnosticFailure(error: error)))
      failSafely(error)
    }
  }

  public func cancel() {
    requestCancellation(origin: .cancelButton)
  }

  public func requestCancellation(
    origin: RecoveryCancellationOrigin,
    decisionHandler: (@MainActor (Bool) -> Void)? = nil
  ) {
    switch phase {
    case .preflighting:
      decisionHandler?(true)
      beginCancellationIfNeeded()
    case .running, .validating:
      if let decisionHandler {
        cancellationDecisionHandlers.append(decisionHandler)
      }
      if let prompt = pendingCancellationPrompt {
        if origin.rawValue > prompt.origin.rawValue {
          pendingCancellationPrompt = RecoveryCancellationPrompt(
            id: prompt.id,
            origin: origin
          )
        }
      } else {
        pendingCancellationPrompt = RecoveryCancellationPrompt(origin: origin)
      }
    case .cancelling:
      decisionHandler?(true)
    case .chooseBackup, .chooseDestination, .confirm, .completed, .failed:
      decisionHandler?(origin != .cancelButton)
    }
  }

  public func continueRecovery() {
    resolveCancellationPrompt(confirmed: false)
  }

  public func confirmCancellation() {
    guard pendingCancellationPrompt != nil else {
      return
    }
    let handlers = takeCancellationDecisionHandlers()
    pendingCancellationPrompt = nil
    beginCancellationIfNeeded()
    for handler in handlers {
      handler(true)
    }
  }

  public func returnToBackupSelection() {
    guard !phase.isBusy else {
      return
    }
    operationTask?.cancel()
    operationTask = nil
    resolveCancellationPrompt(confirmed: false)
    cancellationSignalSent = false
    retainedDestinationLease?.stop()
    retainedDestinationLease = nil
    backupDirectory = nil
    destinationParent = nil
    destinationParentIdentity = nil
    outputDirectory = nil
    preflightSummary = nil
    backupReceipt = nil
    phase = .chooseBackup
  }

  public func recoverFromFailure() {
    guard case .failed(let failure) = phase else {
      return
    }
    switch failure.recoveryPlan.route {
    case .chooseBackup:
      returnToBackupSelection()
    case .chooseDestination:
      goBackToDestinationSelection()
    case .retryPasswordWithFreshOutput, .retryWithFreshOutput:
      retryPreflight(useFreshOutput: true)
    case .retrySamePreflight:
      retryPreflight(useFreshOutput: false)
    case .startOverOnly:
      break
    }
  }

  public func goBackToDestinationSelection() {
    guard !phase.isBusy, backupDirectory != nil else {
      return
    }
    destinationParent = nil
    destinationParentIdentity = nil
    outputDirectory = nil
    preflightSummary = nil
    backupReceipt = nil
    resolveCancellationPrompt(confirmed: false)
    phase = .chooseDestination
  }

  public var destinationDisplayName: String {
    guard let destinationParent else {
      return "Selected private destination"
    }
    let candidate = destinationParent.standardizedFileURL
    let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL
    let values = try? candidate.resourceValues(forKeys: [.volumeNameKey])
    let volume = safeDisplayComponent(values?.volumeName, fallback: "Selected volume")

    let folder: String
    if candidate == home {
      folder = "Home folder"
    } else if candidate.path.hasPrefix(home.path + "/") {
      let relative = candidate.path.dropFirst(home.path.count + 1)
      let components = relative.split(separator: "/").suffix(2).map(String.init)
      folder = safeDisplayComponent(
        components.isEmpty ? nil : components.joined(separator: " › "),
        fallback: "Home folder"
      )
    } else {
      folder = safeDisplayComponent(candidate.lastPathComponent, fallback: "Selected folder")
    }

    return folder == volume ? volume : "\(volume) › \(folder)"
  }

  public var markdownReportURL: URL? {
    guard case .completed(let summary) = phase else {
      return nil
    }
    return artifactURL(relativePath: summary.artifacts.report)
  }

  public var reportURL: URL? {
    markdownReportURL
  }

  public var visualReportURL: URL? {
    guard case .completed(let summary) = phase else {
      return nil
    }
    return artifactURL(relativePath: summary.artifacts.visualReport)
  }

  public var pdfReportURL: URL? {
    guard
      case .completed(let summary) = phase,
      let relativePath = summary.artifacts.pdfReport
    else {
      return nil
    }
    return artifactURL(relativePath: relativePath)
  }

  public var analysisDirectoryURL: URL? {
    guard case .completed(let summary) = phase else {
      return nil
    }
    return artifactURL(relativePath: summary.artifacts.analysisDirectory)
  }

  private func startPreflight() {
    guard
      let backupDirectory,
      let destinationParent,
      let outputDirectory
    else {
      return
    }
    preflightSummary = nil
    backupReceipt = nil
    let sourceLease = SecurityScopedResourceLease(url: backupDirectory)
    let destinationLease = SecurityScopedResourceLease(url: destinationParent)
    do {
      let currentDestinationIdentity = try destinationEncryptionValidator(destinationParent)
      destinationParentIdentity = currentDestinationIdentity
      let request = RecoveryRequest(
        action: .preflight,
        backupDirectory: backupDirectory,
        outputDirectory: outputDirectory,
        destinationParentIdentity: currentDestinationIdentity,
        acknowledgeSensitiveOutput: false
      )
      prepareForOperation()
      activeAction = .preflight
      let stream = try helperClient.events(for: request, secret: nil)
      phase = .preflighting(
        RecoveryProgress(
          stage: "preflight",
          kind: "started",
          message: "Inspecting the backup without modifying it..."
        )
      )
      diagnostics.record(.milestone(.preflight, .started))
      consume(
        stream,
        sourceLease: sourceLease,
        destinationLease: destinationLease,
        retainDestinationOnSuccess: false
      )
    } catch {
      diagnostics.record(.failure(.preflight, RecoveryDiagnosticFailure(error: error)))
      activeAction = nil
      sourceLease.stop()
      destinationLease.stop()
      failSafely(error)
    }
  }

  private func consume(
    _ stream: AsyncThrowingStream<HelperEvent, Error>,
    sourceLease: SecurityScopedResourceLease,
    destinationLease: SecurityScopedResourceLease,
    retainDestinationOnSuccess: Bool
  ) {
    operationTask?.cancel()
    operationTask = Task { [weak self] in
      guard let self else {
        sourceLease.stop()
        destinationLease.stop()
        return
      }
      do {
        for try await event in stream {
          await handle(event)
        }
        sourceLease.stop()
        if retainDestinationOnSuccess, case .completed = phase {
          retainedDestinationLease?.stop()
          retainedDestinationLease = destinationLease
        } else {
          destinationLease.stop()
        }
      } catch {
        sourceLease.stop()
        destinationLease.stop()
        diagnostics.record(
          .failure(
            activeAction?.diagnosticOperation ?? .recovery, RecoveryDiagnosticFailure(error: error))
        )
        failSafely(error)
      }
      operationTask = nil
    }
  }

  private func handle(_ event: HelperEvent) async {
    switch event.body {
    case .ready:
      break
    case .progress(let event):
      let progress = event.recoveryProgress
      if case .preflighting = phase {
        phase = .preflighting(progress)
      } else if case .cancelling = phase {
        break
      } else if case .validating = phase {
        break
      } else {
        phase = .running(progress)
      }
    case .preflightCompleted(let completion):
      diagnostics.record(.milestone(.preflight, .completed))
      cancelPendingInterruptionRequests()
      activeAction = nil
      let summary = completion.summary
      preflightSummary = summary
      backupReceipt = completion.backupReceipt
      phase = .confirm(summary)
    case .recoveryCompleted(let summary):
      cancelPendingInterruptionRequests()
      activeAction = nil
      backupReceipt = nil
      guard !cancellationSignalSent else {
        failCancellation(for: .recovery)
        return
      }
      do {
        guard let outputDirectory else {
          throw RecoveryOutputValidationError.missingArtifact
        }
        phase = .validating(
          RecoveryProgress(
            stage: "validation",
            kind: "started",
            message: "Validating recovered output…"
          )
        )
        diagnostics.record(.milestone(.recovery, .completed))
        diagnostics.record(.milestone(.validation, .started))
        try await validateRecoveryOutput(summary, beneath: outputDirectory)
        guard !cancellationSignalSent, case .validating = phase else {
          throw CancellationError()
        }
        cancelPendingInterruptionRequests()
        preflightSummary = summary.preflight
        phase = .completed(summary)
        diagnostics.record(.milestone(.validation, .completed))
      } catch is CancellationError {
        failValidationCancellation()
      } catch {
        if cancellationSignalSent {
          failValidationCancellation()
        } else {
          failOutputValidation(error)
        }
      }
    case .failed(let failure):
      cancelPendingInterruptionRequests()
      let failedAction = activeAction
      activeAction = nil
      backupReceipt = nil
      diagnostics.record(
        .failure(
          failedAction?.diagnosticOperation ?? .recovery, .init(recoveryFailureCode: failure.code))
      )
      phase = .failed(failure)
    case .cancelled(let failure):
      cancelPendingInterruptionRequests()
      let cancelledAction = activeAction
      activeAction = nil
      backupReceipt = nil
      if cancelledAction == .preflight {
        diagnostics.record(.milestone(.preflight, .cancelled))
        phase = .failed(
          RecoveryFailure(
            code: "preflight_cancelled",
            message: "The selected backup and private storage were not modified.",
            retryable: true
          )
        )
      } else {
        diagnostics.record(.milestone(.recovery, .cancelled))
        phase = .failed(failure)
      }
    }
  }

  private func failSafely(_ error: Error) {
    cancelPendingInterruptionRequests()
    activeAction = nil
    backupReceipt = nil
    if let destinationError = error as? EncryptedDestinationValidationError {
      let failure: RecoveryFailure
      switch destinationError {
      case .encryptionNotConfirmed:
        failure = RecoveryFailure(
          code: "destination_unencrypted",
          message:
            "macOS could not verify the app-managed private storage. No private output was written.",
          retryable: true
        )
      case .localStorageNotConfirmed, .cloudOrSharedLocation, .identityNotConfirmed:
        failure = RecoveryFailure(
          code: "unsafe_path",
          message:
            "macOS could not confirm app-managed private local storage outside cloud or shared storage. No private output was written.",
          retryable: true
        )
      }
      phase = .failed(
        failure
      )
      return
    }
    let message =
      (error as? LocalizedError)?.errorDescription
      ?? "Recovery stopped safely before completion."
    phase = .failed(
      RecoveryFailure(
        code: "local_helper_error",
        message: message,
        retryable: true
      )
    )
  }

  private func failOutputValidation(_ error: Error) {
    cancelPendingInterruptionRequests()
    backupReceipt = nil
    diagnostics.record(.failure(.validation, RecoveryDiagnosticFailure(error: error)))
    let message =
      (error as? LocalizedError)?.errorDescription
      ?? "The recovered output could not be validated safely. Preserve it for review."
    phase = .failed(
      RecoveryFailure(
        code: "output_validation_failed",
        message: message,
        retryable: true
      )
    )
  }

  private func failValidationCancellation() {
    failCancellation(for: .validation)
  }

  private func failCancellation(for operation: RecoveryDiagnosticOperation) {
    cancelPendingInterruptionRequests()
    backupReceipt = nil
    diagnostics.record(.milestone(operation, .cancelled))
    let message =
      operation == .recovery
      ? "Recovery was cancelled. The incomplete output was preserved."
      : "Verification was cancelled. The unverified output was preserved."
    phase = .failed(
      RecoveryFailure(
        code: "cancelled",
        message: message,
        retryable: true
      )
    )
  }

  private func prepareForOperation() {
    resolveCancellationPrompt(confirmed: false)
    cancellationSignalSent = false
  }

  private func beginCancellationIfNeeded() {
    guard phase.isBusy, !cancellationSignalSent else {
      return
    }
    let isValidating: Bool
    if case .validating = phase {
      isValidating = true
    } else {
      isValidating = false
    }
    cancellationSignalSent = true
    diagnostics.record(
      .milestone(activeAction?.diagnosticOperation ?? .validation, .cancellationRequested)
    )
    phase = .cancelling
    if isValidating {
      validationTask?.cancel()
    } else {
      helperClient.cancel()
    }
  }

  private func validateRecoveryOutput(
    _ summary: RecoverySummary,
    beneath outputDirectory: URL
  ) async throws {
    let validator = recoveryOutputValidator
    let task = Task.detached(priority: .userInitiated) {
      try validator(summary, outputDirectory)
    }
    validationTask = task
    defer { validationTask = nil }
    try await withTaskCancellationHandler {
      try await task.value
    } onCancel: {
      task.cancel()
    }
  }

  private func resolveCancellationPrompt(confirmed: Bool) {
    guard pendingCancellationPrompt != nil || !cancellationDecisionHandlers.isEmpty else {
      return
    }
    pendingCancellationPrompt = nil
    let handlers = takeCancellationDecisionHandlers()
    for handler in handlers {
      handler(confirmed)
    }
  }

  private func cancelPendingInterruptionRequests() {
    // A helper terminal event is not user consent to quit or close. Only the destructive
    // confirmation action may resolve an interruption request as approved.
    resolveCancellationPrompt(confirmed: false)
  }

  private func takeCancellationDecisionHandlers() -> [@MainActor (Bool) -> Void] {
    let handlers = cancellationDecisionHandlers
    cancellationDecisionHandlers.removeAll(keepingCapacity: false)
    return handlers
  }

  private func retryPreflight(useFreshOutput: Bool) {
    guard
      !phase.isBusy,
      backupDirectory != nil,
      let destinationParent,
      outputDirectory != nil
    else {
      returnToBackupSelection()
      return
    }
    retainedDestinationLease?.stop()
    retainedDestinationLease = nil
    resolveCancellationPrompt(confirmed: false)
    cancellationSignalSent = false
    preflightSummary = nil
    backupReceipt = nil
    if useFreshOutput {
      outputDirectory = freshOutputDirectory(
        in: destinationParent,
        excluding: outputDirectory
      )
    }
    startPreflight()
  }

  private func freshOutputDirectory(in parent: URL, excluding excluded: URL? = nil) -> URL {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.calendar = Calendar(identifier: .gregorian)
    formatter.timeZone = .current
    formatter.dateFormat = "yyyyMMdd-HHmmss"
    let baseName = "TVTime-Recovery-\(formatter.string(from: Date()))"
    var candidate = parent.appendingPathComponent(baseName, isDirectory: true)
    let excluded = excluded?.standardizedFileURL
    var suffix = 2
    while candidate.standardizedFileURL == excluded
      || FileManager.default.fileExists(atPath: candidate.path)
    {
      candidate = parent.appendingPathComponent("\(baseName)-\(suffix)", isDirectory: true)
      suffix += 1
    }
    return candidate.standardizedFileURL
  }

  private func artifactURL(relativePath: String) -> URL? {
    guard let outputDirectory else {
      return nil
    }
    let components = relativePath.split(separator: "/", omittingEmptySubsequences: false)
    guard
      !components.isEmpty,
      components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
    else {
      return nil
    }
    let candidate = components.reduce(outputDirectory) { partial, component in
      partial.appendingPathComponent(String(component))
    }.standardizedFileURL
    let root = outputDirectory.standardizedFileURL
    guard candidate.path.hasPrefix(root.path + "/") else {
      return nil
    }
    return candidate
  }

  private func safeDisplayComponent(_ value: String?, fallback: String) -> String {
    guard let value else {
      return fallback
    }
    let cleaned = value
      .unicodeScalars
      .filter { !CharacterSet.controlCharacters.contains($0) }
      .map(String.init)
      .joined()
      .trimmingCharacters(in: .whitespacesAndNewlines)
    guard !cleaned.isEmpty else {
      return fallback
    }
    return String(cleaned.prefix(80))
  }
}
