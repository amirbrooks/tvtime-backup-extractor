import Foundation
import Testing

@testable import TVTimeRecoveryCore

private let syntheticDestinationIdentity = DestinationDirectoryIdentity(device: 7, inode: 11)

@Suite(.serialized)
@MainActor
final class RecoverySessionTests {
  private var temporaryDirectories: [URL] = []

  deinit {
    for directory in temporaryDirectories {
      try? FileManager.default.removeItem(at: directory)
    }
  }

  @Test
  func testSelectionStandardizesPathsAndCreatesFreshChildOutput() throws {
    let helper = FakeRecoveryHelperClient()
    let session = RecoverySession(
      helperClient: helper,
      destinationEncryptionValidator: { _ in syntheticDestinationIdentity }
    )
    let root = try trackedDirectory()
    let backup = root.appendingPathComponent("a/../backup")
    let destination = root.appendingPathComponent("destination/.")

    session.selectBackup(backup)
    expectEqual(session.backupDirectory, backup.standardizedFileURL)
    expectEqual(session.phase, .chooseDestination)

    session.selectDestinationParent(destination)
    expectEqual(session.destinationParent, destination.standardizedFileURL)
    let output = try requireValue(session.outputDirectory)
    expectEqual(output.deletingLastPathComponent(), destination.standardizedFileURL)
    expectTrue(output.lastPathComponent.hasPrefix("TVTime-Recovery-"))
    expectEqual(helper.invocations.map(\.request.action), [.preflight])
  }

  @Test
  func testAppManagedSelectionStartsPreflightWithoutDestinationPhase() throws {
    let helper = FakeRecoveryHelperClient()
    let session = RecoverySession(
      helperClient: helper,
      destinationEncryptionValidator: { _ in syntheticDestinationIdentity }
    )
    let root = try trackedDirectory()
    let backup = root.appendingPathComponent("backup", isDirectory: true)
    let destination = root.appendingPathComponent("app-managed", isDirectory: true)
    try makePrivateDirectory(backup)
    try makePrivateDirectory(destination)

    session.selectBackup(backup, appManagedDestinationParent: destination)

    expectEqual(session.backupDirectory, backup.standardizedFileURL)
    expectEqual(session.destinationParent, destination.standardizedFileURL)
    let output = try requireValue(session.outputDirectory)
    expectEqual(output.deletingLastPathComponent(), destination.standardizedFileURL)
    guard case .preflighting = session.phase else {
      return failTest("Expected direct app-managed selection to start preflight")
    }
    expectEqual(helper.invocations.map(\.request.action), [.preflight])
  }

  @Test
  func testPreflightCompletionEnablesRecoveryAndPassesSecretOnlyToRecovery() async throws {
    let context = try makePreflightingSession()
    let receipt = TestFixtures.backupReceipt()
    expectNil(context.helper.invocations[0].secret)
    expectNil(context.helper.invocations[0].request.backupReceipt)

    context.helper.send(
      try TestFixtures.preflightCompletionEvent(backupReceipt: receipt),
      finish: true
    )
    try await waitUntil { context.session.phase == .confirm(TestFixtures.preflight()) }

    context.session.startRecovery(password: "local-test-password", acknowledgeSensitiveOutput: true)
    expectEqual(context.helper.invocations.map(\.request.action), [.preflight, .recover])
    expectEqual(
      context.helper.invocations.map(\.request.destinationParentIdentity),
      [syntheticDestinationIdentity, syntheticDestinationIdentity]
    )
    expectEqual(context.helper.invocations[1].secret, Data("local-test-password".utf8))
    expectEqual(context.helper.invocations[1].request.backupReceipt, receipt)
    guard case .running = context.session.phase else {
      return failTest("Expected running phase")
    }
  }

  @Test
  func testNewSelectionsAndRetryPreflightDoNotReuseAStaleBackupReceipt() async throws {
    let sourceContext = try makePreflightingSession()
    sourceContext.helper.send(try TestFixtures.preflightCompletionEvent(), finish: true)
    try await waitUntil { sourceContext.session.phase == .confirm(TestFixtures.preflight()) }
    let sourceRoot = try requireValue(sourceContext.session.backupDirectory)
      .deletingLastPathComponent()
    let replacementBackup = sourceRoot.appendingPathComponent(
      "replacement-backup",
      isDirectory: true
    )
    let replacementDestination = sourceRoot.appendingPathComponent(
      "replacement-destination",
      isDirectory: true
    )
    try makePrivateDirectory(replacementBackup)
    try makePrivateDirectory(replacementDestination)
    sourceContext.session.selectBackup(replacementBackup)
    sourceContext.session.selectDestinationParent(replacementDestination)
    expectNil(sourceContext.helper.invocations.last?.request.backupReceipt)

    let destinationContext = try makePreflightingSession()
    destinationContext.helper.send(try TestFixtures.preflightCompletionEvent(), finish: true)
    try await waitUntil {
      destinationContext.session.phase == .confirm(TestFixtures.preflight())
    }
    let destinationRoot = try requireValue(destinationContext.session.destinationParent)
      .deletingLastPathComponent()
    let newDestination = destinationRoot.appendingPathComponent(
      "new-destination",
      isDirectory: true
    )
    try makePrivateDirectory(newDestination)
    destinationContext.session.selectDestinationParent(newDestination)
    expectNil(destinationContext.helper.invocations.last?.request.backupReceipt)

    let retryContext = try await makeRunningSession()
    expectEqual(
      retryContext.helper.invocations.last?.request.backupReceipt,
      TestFixtures.backupReceipt()
    )
    try await deliverFailure(code: "recovery_failed", to: retryContext)
    retryContext.session.recoverFromFailure()
    expectNil(retryContext.helper.invocations.last?.request.backupReceipt)
    guard case .preflighting = retryContext.session.phase else {
      return failTest("Expected retry to require a new preflight receipt")
    }
  }

  @Test
  func testMissingReceiptCompletionCannotStartRecovery() async throws {
    let context = try makePreflightingSession()
    let preflight = try JSONSerialization.jsonObject(
      with: JSONEncoder().encode(TestFixtures.preflight())
    )
    let envelope: [String: Any] = [
      "protocolVersion": HelperProtocolV3.version,
      "sequence": 2,
      "type": "completed",
      "payload": ["preflight": preflight],
    ]
    let decodingFailure: Error
    do {
      _ = try HelperEventDecoder.decode(
        JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
      )
      return failTest("Expected a missing backup receipt to fail decoding")
    } catch {
      decodingFailure = error
    }

    context.helper.finish(throwing: decodingFailure)
    try await waitUntil {
      guard case .failed(let failure) = context.session.phase else { return false }
      return failure.code == "local_helper_error"
    }
    context.session.startRecovery(password: "password", acknowledgeSensitiveOutput: true)
    expectEqual(context.helper.invocations.map(\.request.action), [.preflight])
  }

  @Test
  func testPrivateEncryptedLocalDestinationIsRequiredAndRecheckedBeforeRecovery() async throws {
    let rejectedHelper = FakeRecoveryHelperClient()
    let rejectedSession = RecoverySession(
      helperClient: rejectedHelper,
      destinationEncryptionValidator: { _ in
        throw EncryptedDestinationValidationError.encryptionNotConfirmed
      }
    )
    let rejectedRoot = try trackedDirectory()
    rejectedSession.selectBackup(rejectedRoot.appendingPathComponent("backup"))
    rejectedSession.selectDestinationParent(rejectedRoot.appendingPathComponent("destination"))
    guard case .failed(let rejectedFailure) = rejectedSession.phase else {
      return failTest("Expected unverified destination to fail before preflight")
    }
    expectEqual(rejectedFailure.code, "destination_unencrypted")
    expectEqual(rejectedHelper.invocations.count, 0)

    let cloudHelper = FakeRecoveryHelperClient()
    let cloudSession = RecoverySession(
      helperClient: cloudHelper,
      destinationEncryptionValidator: { _ in
        throw EncryptedDestinationValidationError.cloudOrSharedLocation
      }
    )
    let cloudRoot = try trackedDirectory()
    cloudSession.selectBackup(cloudRoot.appendingPathComponent("backup"))
    cloudSession.selectDestinationParent(cloudRoot.appendingPathComponent("destination"))
    guard case .failed(let cloudFailure) = cloudSession.phase else {
      return failTest("Expected a cloud or shared destination to fail before preflight")
    }
    expectEqual(cloudFailure.code, "unsafe_path")
    expectEqual(cloudHelper.invocations.count, 0)

    let remountedHelper = FakeRecoveryHelperClient()
    var validationCount = 0
    let remountedSession = RecoverySession(
      helperClient: remountedHelper,
      destinationEncryptionValidator: { _ in
        validationCount += 1
        if validationCount > 1 {
          throw EncryptedDestinationValidationError.encryptionNotConfirmed
        }
        return syntheticDestinationIdentity
      }
    )
    let remountedRoot = try trackedDirectory()
    remountedSession.selectBackup(remountedRoot.appendingPathComponent("backup"))
    remountedSession.selectDestinationParent(remountedRoot.appendingPathComponent("destination"))
    expectEqual(remountedHelper.invocations.map(\.request.action), [.preflight])
    remountedHelper.send(try TestFixtures.preflightCompletionEvent(), finish: true)
    try await waitUntil { remountedSession.phase == .confirm(TestFixtures.preflight()) }

    remountedSession.startRecovery(password: "password", acknowledgeSensitiveOutput: true)
    guard case .failed(let remountedFailure) = remountedSession.phase else {
      return failTest("Expected encryption to be rechecked immediately before recovery")
    }
    expectEqual(remountedFailure.code, "destination_unencrypted")
    expectEqual(remountedHelper.invocations.map(\.request.action), [.preflight])
    expectEqual(validationCount, 2)
  }

  @Test
  func testDestinationIdentityMustMatchFromPreflightThroughRecovery() async throws {
    let helper = FakeRecoveryHelperClient()
    var validationCount = 0
    let session = RecoverySession(
      helperClient: helper,
      destinationEncryptionValidator: { _ in
        validationCount += 1
        return DestinationDirectoryIdentity(
          device: 7,
          inode: validationCount == 1 ? 11 : 12
        )
      }
    )
    let root = try trackedDirectory()
    session.selectBackup(root.appendingPathComponent("backup", isDirectory: true))
    session.selectDestinationParent(root.appendingPathComponent("destination", isDirectory: true))
    helper.send(try TestFixtures.preflightCompletionEvent(), finish: true)
    try await waitUntil { session.phase == .confirm(TestFixtures.preflight()) }

    session.startRecovery(password: "password", acknowledgeSensitiveOutput: true)

    guard case .failed(let failure) = session.phase else {
      return failTest("Expected a substituted destination identity to fail closed")
    }
    expectEqual(failure.code, "unsafe_path")
    expectEqual(helper.invocations.map(\.request.action), [.preflight])
    expectEqual(validationCount, 2)
  }

  @Test
  func testPreflightCancellationIsImmediateIdempotentAndSafelyClassified() async throws {
    let context = try makePreflightingSession()
    let originalOutput = try requireValue(context.session.outputDirectory)
    var decisions: [Bool] = []

    context.session.requestCancellation(origin: .applicationQuit) { decisions.append($0) }
    expectEqual(decisions, [true])
    expectEqual(context.session.phase, .cancelling)
    expectEqual(context.helper.cancelCount, 1)

    context.session.requestCancellation(origin: .windowClose) { decisions.append($0) }
    expectEqual(decisions, [true, true])
    expectEqual(context.helper.cancelCount, 1)

    let cancellation = RecoveryFailure(code: "cancelled", message: "Cancelled", retryable: true)
    context.helper.send(
      try TestFixtures.event(type: "cancelled", payload: cancellation),
      finish: true
    )
    try await waitUntil {
      guard case .failed(let failure) = context.session.phase else { return false }
      return failure.code == "preflight_cancelled"
    }

    context.session.recoverFromFailure()
    expectEqual(context.session.outputDirectory, originalOutput)
    expectNil(context.session.preflightSummary)
    expectEqual(context.helper.invocations.map(\.request.action), [.preflight, .preflight])
    guard case .preflighting = context.session.phase else {
      return failTest("Expected the same read-only preflight to rerun")
    }

    let refreshedSummary = TestFixtures.preflight(backupRegularFiles: 101)
    context.helper.send(
      try TestFixtures.preflightCompletionEvent(refreshedSummary),
      finish: true
    )
    try await waitUntil { context.session.phase == .confirm(refreshedSummary) }
  }

  @Test
  func testRunningCancellationCanContinueOrConfirmAndUpgradesPromptOrigin() async throws {
    let context = try await makeRunningSession()
    var windowDecisions: [Bool] = []
    var quitDecisions: [Bool] = []

    context.session.requestCancellation(origin: .windowClose) { windowDecisions.append($0) }
    let firstPrompt = try requireValue(context.session.pendingCancellationPrompt)
    expectEqual(firstPrompt.origin, .windowClose)
    expectEqual(context.helper.cancelCount, 0)

    context.session.requestCancellation(origin: .applicationQuit) { quitDecisions.append($0) }
    let upgradedPrompt = try requireValue(context.session.pendingCancellationPrompt)
    expectEqual(upgradedPrompt.id, firstPrompt.id)
    expectEqual(upgradedPrompt.origin, .applicationQuit)

    context.session.continueRecovery()
    expectEqual(windowDecisions, [false])
    expectEqual(quitDecisions, [false])
    expectNil(context.session.pendingCancellationPrompt)
    expectEqual(context.helper.cancelCount, 0)

    context.session.requestCancellation(origin: .applicationQuit) { quitDecisions.append($0) }
    context.session.confirmCancellation()
    expectEqual(quitDecisions, [false, true])
    expectEqual(context.session.phase, .cancelling)
    expectEqual(context.helper.cancelCount, 1)

    context.session.confirmCancellation()
    expectEqual(context.helper.cancelCount, 1)
  }

  @Test
  func testPendingCmdQIsDeniedWhenRecoveryCompletesNaturally() async throws {
    let context = try await makeRunningSession()
    let output = try requireValue(context.session.outputDirectory)
    try TestFixtures.makePrivateOutput(at: output)
    var quitDecisions: [Bool] = []

    context.session.requestCancellation(origin: .applicationQuit) { quitDecisions.append($0) }
    expectEqual(context.session.pendingCancellationPrompt?.origin, .applicationQuit)

    context.helper.send(try TestFixtures.recoveryCompletionEvent(), finish: true)
    try await waitUntil {
      guard case .completed = context.session.phase else { return false }
      return true
    }

    expectEqual(quitDecisions, [false], "Natural completion must never authorize Cmd-Q")
    expectNil(context.session.pendingCancellationPrompt)
    expectEqual(context.helper.cancelCount, 0)
    expectEqual(
      context.session.markdownReportURL,
      output.appendingPathComponent(RecoveryArtifacts.expectedReport))
    expectEqual(
      context.session.visualReportURL,
      output.appendingPathComponent(RecoveryArtifacts.expectedVisualReport)
    )
    expectEqual(
      context.session.pdfReportURL,
      output.appendingPathComponent(RecoveryArtifacts.expectedPDFReport)
    )
  }

  @Test
  func testRecoveryCompletionValidatesOffMainBeforePublishingSuccess() async throws {
    let gate = ValidationGate()
    let context = try await makeRunningSession(validationGate: gate)
    let output = try requireValue(context.session.outputDirectory)

    context.helper.send(try TestFixtures.recoveryCompletionEvent(), finish: true)
    try await waitUntil {
      guard case .validating(let progress) = context.session.phase else { return false }
      return progress.stage == "validation"
        && progress.message == "Validating recovered output…"
        && gate.hasStarted
    }

    expectFalse(gate.ranOnMainThread)
    expectEqual(gate.outputDirectory, output)
    gate.release()
    try await waitUntil {
      guard case .completed = context.session.phase else { return false }
      return true
    }
  }

  @Test
  func testValidationCancellationIsCooperativeAndDoesNotSignalExitedHelper() async throws {
    let gate = ValidationGate()
    let context = try await makeRunningSession(validationGate: gate)
    context.helper.send(try TestFixtures.recoveryCompletionEvent(), finish: true)
    try await waitUntil {
      guard case .validating = context.session.phase else { return false }
      return gate.hasStarted
    }

    context.session.cancel()
    expectEqual(context.session.pendingCancellationPrompt?.origin, .cancelButton)
    context.session.confirmCancellation()
    expectEqual(context.session.phase, .cancelling)
    expectEqual(context.helper.cancelCount, 0)

    try await waitUntil {
      guard case .failed(let failure) = context.session.phase else { return false }
      return failure.code == "cancelled"
        && failure.message == "Verification was cancelled. The unverified output was preserved."
    }
    expectEqual(context.helper.cancelCount, 0)
    expectEqual(context.session.preflightSummary, TestFixtures.preflight())
  }

  @Test
  func testValidationCompletionDeniesPendingCloseAndQuitWithoutLeavingAStalePrompt()
    async throws
  {
    let gate = ValidationGate()
    defer { gate.release() }
    let context = try await makeRunningSession(validationGate: gate)
    context.helper.send(try TestFixtures.recoveryCompletionEvent(), finish: true)
    try await waitUntil {
      guard case .validating = context.session.phase else { return false }
      return gate.hasStarted
    }

    var closeDecisions: [Bool] = []
    var quitDecisions: [Bool] = []
    context.session.requestCancellation(origin: .windowClose) {
      closeDecisions.append($0)
    }
    context.session.requestCancellation(origin: .applicationQuit) {
      quitDecisions.append($0)
    }
    expectEqual(context.session.pendingCancellationPrompt?.origin, .applicationQuit)

    gate.release()
    try await waitUntil {
      guard case .completed = context.session.phase else { return false }
      return true
    }

    expectEqual(closeDecisions, [false])
    expectEqual(quitDecisions, [false])
    expectNil(context.session.pendingCancellationPrompt)
    expectEqual(context.helper.cancelCount, 0)
  }

  @Test
  func testValidationFailureDeniesPendingCloseAndQuitWithoutLeavingAStalePrompt() async throws {
    let gate = ValidationGate(terminalError: FakeError.communication)
    defer { gate.release() }
    let context = try await makeRunningSession(validationGate: gate)
    context.helper.send(try TestFixtures.recoveryCompletionEvent(), finish: true)
    try await waitUntil {
      guard case .validating = context.session.phase else { return false }
      return gate.hasStarted
    }

    var closeDecision: Bool?
    var quitDecision: Bool?
    context.session.requestCancellation(origin: .windowClose) { closeDecision = $0 }
    context.session.requestCancellation(origin: .applicationQuit) { quitDecision = $0 }
    gate.release()

    try await waitUntil {
      guard case .failed(let failure) = context.session.phase else { return false }
      return failure.code == "output_validation_failed"
    }
    expectEqual(closeDecision, false)
    expectEqual(quitDecision, false)
    expectNil(context.session.pendingCancellationPrompt)
    expectEqual(context.helper.cancelCount, 0)
  }

  @Test
  func testConfirmedRecoveryCancellationCannotPublishACompetingCompletion() async throws {
    let gate = ValidationGate()
    let diagnostics = RecordingRecoveryDiagnostics()
    let context = try await makeRunningSession(
      validationGate: gate,
      diagnostics: diagnostics
    )

    context.session.cancel()
    context.session.confirmCancellation()
    expectEqual(context.session.phase, .cancelling)
    expectEqual(context.helper.cancelCount, 1)

    context.helper.send(try TestFixtures.recoveryCompletionEvent(), finish: true)
    try await waitUntil {
      guard case .failed(let failure) = context.session.phase else { return false }
      return failure.code == "cancelled"
        && failure.message == "Recovery was cancelled. The incomplete output was preserved."
    }
    expectFalse(gate.hasStarted)
    expectEqual(
      Array(diagnostics.events.suffix(2)),
      [
        .milestone(.recovery, .cancellationRequested),
        .milestone(.recovery, .cancelled),
      ]
    )
  }

  @Test
  func testPendingQuitIsDeniedWhenHelperFailsOrCancelsNaturally() async throws {
    let failureContext = try await makeRunningSession()
    var failureDecision: Bool?
    failureContext.session.requestCancellation(origin: .applicationQuit) {
      failureDecision = $0
    }
    let failure = RecoveryFailure(code: "helper_failed", message: "Stopped", retryable: true)
    failureContext.helper.send(
      try TestFixtures.event(type: "failed", payload: failure), finish: true)
    try await waitUntil { failureContext.session.phase == .failed(failure) }
    expectEqual(failureDecision, false)

    let cancelContext = try await makeRunningSession()
    var cancelDecision: Bool?
    cancelContext.session.requestCancellation(origin: .applicationQuit) {
      cancelDecision = $0
    }
    let cancellation = RecoveryFailure(code: "cancelled", message: "Cancelled", retryable: true)
    cancelContext.helper.send(
      try TestFixtures.event(type: "cancelled", payload: cancellation),
      finish: true
    )
    try await waitUntil { cancelContext.session.phase == .failed(cancellation) }
    expectEqual(cancelDecision, false)
  }

  @Test
  func testStreamErrorDeniesPendingQuitAndFailsSafely() async throws {
    let context = try await makeRunningSession()
    var quitDecision: Bool?
    context.session.requestCancellation(origin: .applicationQuit) { quitDecision = $0 }

    context.helper.finish(throwing: FakeError.communication)
    try await waitUntil {
      guard case .failed(let failure) = context.session.phase else { return false }
      return failure.code == "local_helper_error"
    }
    expectEqual(quitDecision, false)
    expectNil(context.session.pendingCancellationPrompt)
  }

  @Test
  func testBackupFailureRouteReturnsToBackupSelectionAndClearsStaleState() async throws {
    let context = try await makeRunningSession()
    let originalBackup = try requireValue(context.session.backupDirectory)
    try await deliverFailure(code: "backup_unencrypted", to: context)
    expectEqual(context.session.preflightSummary, TestFixtures.preflight())

    context.session.recoverFromFailure()

    expectEqual(context.session.phase, .chooseBackup)
    expectNil(context.session.backupDirectory)
    expectNil(context.session.destinationParent)
    expectNil(context.session.outputDirectory)
    expectNil(context.session.preflightSummary)
    expectEqual(context.helper.invocations.map(\.request.action), [.preflight, .recover])

    let root = originalBackup.deletingLastPathComponent()
    let replacementBackup = root.appendingPathComponent("replacement-backup", isDirectory: true)
    let replacementDestination = root.appendingPathComponent(
      "replacement-destination",
      isDirectory: true
    )
    try makePrivateDirectory(replacementBackup)
    try makePrivateDirectory(replacementDestination)
    context.session.selectBackup(replacementBackup)
    context.session.selectDestinationParent(replacementDestination)

    expectNil(context.session.preflightSummary)
    expectEqual(
      context.helper.invocations.map(\.request.action),
      [.preflight, .recover, .preflight]
    )
    guard case .preflighting = context.session.phase else {
      return failTest("Expected replacement selections to start a new preflight")
    }
  }

  @Test
  func testAppManagedStorageFailureOffersOnlyExplicitStartOver() async throws {
    let context = try await makeRunningSession()
    let selectedBackup = context.session.backupDirectory
    let selectedDestination = context.session.destinationParent
    let selectedOutput = context.session.outputDirectory
    try await deliverFailure(code: "insufficient_space", to: context)
    expectEqual(context.session.preflightSummary, TestFixtures.preflight())

    context.session.recoverFromFailure()

    guard case .failed(let failure) = context.session.phase else {
      return failTest("Expected app-managed storage failures to remain failed until Start Over")
    }
    expectEqual(failure.code, "insufficient_space")
    expectEqual(context.session.backupDirectory, selectedBackup)
    expectEqual(context.session.destinationParent, selectedDestination)
    expectEqual(context.session.outputDirectory, selectedOutput)
    expectEqual(context.session.preflightSummary, TestFixtures.preflight())
    expectEqual(context.helper.invocations.map(\.request.action), [.preflight, .recover])

    context.session.returnToBackupSelection()

    expectEqual(context.session.phase, .chooseBackup)
    expectNil(context.session.backupDirectory)
    expectNil(context.session.destinationParent)
    expectNil(context.session.outputDirectory)
    expectNil(context.session.preflightSummary)
    expectEqual(context.helper.invocations.map(\.request.action), [.preflight, .recover])
  }

  @Test
  func testPasswordFailureCreatesFreshOutputAndRequiresNewPreflightBeforeConfirmation()
    async throws
  {
    let context = try await makeRunningSession()
    let originalOutput = try requireValue(context.session.outputDirectory)
    try await deliverFailure(code: "backup_password_rejected", to: context)
    expectEqual(context.session.preflightSummary, TestFixtures.preflight())

    context.session.recoverFromFailure()

    let freshOutput = try requireValue(context.session.outputDirectory)
    expectNotEqual(freshOutput, originalOutput)
    expectEqual(freshOutput.deletingLastPathComponent(), originalOutput.deletingLastPathComponent())
    expectNil(context.session.preflightSummary)
    expectEqual(
      context.helper.invocations.map(\.request.action),
      [.preflight, .recover, .preflight]
    )
    expectNil(context.helper.invocations.last?.secret)
    guard case .preflighting = context.session.phase else {
      return failTest("Expected password recovery to rerun preflight")
    }

    let refreshedSummary = TestFixtures.preflight(backupRegularFiles: 102)
    context.helper.send(
      try TestFixtures.preflightCompletionEvent(refreshedSummary),
      finish: true
    )
    try await waitUntil { context.session.phase == .confirm(refreshedSummary) }
    expectEqual(context.session.preflightSummary, refreshedSummary)
  }

  @Test
  func testRecoveryFailureCodesCreateFreshOutputAndRerunPreflight() async throws {
    for code in ["cancelled", "partial_extraction", "recovery_failed", "local_helper_error"] {
      let context = try await makeRunningSession()
      let originalOutput = try requireValue(context.session.outputDirectory)
      try await deliverFailure(
        code: code,
        eventType: code == "cancelled" ? "cancelled" : "failed",
        to: context
      )
      expectEqual(context.session.preflightSummary, TestFixtures.preflight(), code)

      context.session.recoverFromFailure()

      expectNotEqual(context.session.outputDirectory, originalOutput, code)
      expectNil(context.session.preflightSummary, code)
      expectEqual(
        context.helper.invocations.map(\.request.action),
        [.preflight, .recover, .preflight],
        code
      )
      guard case .preflighting = context.session.phase else {
        failTest("Expected a new preflight for \(code)")
        continue
      }

      let refreshedSummary = TestFixtures.preflight(backupRegularFiles: 103)
      context.helper.send(
        try TestFixtures.preflightCompletionEvent(refreshedSummary),
        finish: true
      )
      try await waitUntil { context.session.phase == .confirm(refreshedSummary) }
    }
  }

  @Test
  func testInvalidCompletionOutputFailsClosed() async throws {
    let context = try await makeRunningSession()
    let output = try requireValue(context.session.outputDirectory)
    try TestFixtures.makePrivateOutput(
      at: output,
      markerOverrides: ["status": "running"]
    )

    context.helper.send(try TestFixtures.recoveryCompletionEvent(), finish: true)
    try await waitUntil {
      guard case .failed(let failure) = context.session.phase else { return false }
      return failure.code == "output_validation_failed"
    }

    expectEqual(context.session.preflightSummary, TestFixtures.preflight())
    context.session.recoverFromFailure()
    expectNotEqual(context.session.outputDirectory, output)
    expectNil(context.session.preflightSummary)
    expectEqual(
      context.helper.invocations.map(\.request.action),
      [.preflight, .recover, .preflight]
    )
    guard case .preflighting = context.session.phase else {
      return failTest("Expected output-validation recovery to rerun preflight")
    }
  }

  @Test
  func testNonBusyInterruptionDecisionDoesNotCancelHelper() {
    let helper = FakeRecoveryHelperClient()
    let session = RecoverySession(
      helperClient: helper,
      destinationEncryptionValidator: { _ in syntheticDestinationIdentity }
    )
    var quitDecision: Bool?
    var cancelDecision: Bool?

    session.requestCancellation(origin: .applicationQuit) { quitDecision = $0 }
    session.requestCancellation(origin: .cancelButton) { cancelDecision = $0 }

    expectEqual(quitDecision, true)
    expectEqual(cancelDecision, false)
    expectEqual(helper.cancelCount, 0)
  }

  @Test
  func testAppManagedSuccessEmitsOnlyBoundedLifecycleDiagnostics() async throws {
    let diagnostics = RecordingRecoveryDiagnostics()
    let helper = FakeRecoveryHelperClient()
    let session = RecoverySession(
      helperClient: helper,
      diagnostics: diagnostics,
      destinationEncryptionValidator: { _ in syntheticDestinationIdentity }
    )
    let root = try trackedDirectory()
    let backup = root.appendingPathComponent("private-backup-identifier", isDirectory: true)
    let destination = root.appendingPathComponent("private-output-path", isDirectory: true)
    try makePrivateDirectory(backup)
    try makePrivateDirectory(destination)

    session.selectBackup(backup, appManagedDestinationParent: destination)
    helper.send(try TestFixtures.preflightCompletionEvent(), finish: true)
    try await waitUntil { session.phase == .confirm(TestFixtures.preflight()) }
    session.startRecovery(password: "do-not-log", acknowledgeSensitiveOutput: true)
    let output = try requireValue(session.outputDirectory)
    try TestFixtures.makePrivateOutput(at: output)
    helper.send(try TestFixtures.recoveryCompletionEvent(), finish: true)
    try await waitUntil {
      guard case .completed = session.phase else { return false }
      return true
    }

    expectEqual(
      diagnostics.events,
      [
        .milestone(.backupPicker, .backupAccepted),
        .milestone(.preflight, .requested),
        .milestone(.preflight, .started),
        .milestone(.preflight, .completed),
        .milestone(.recovery, .requested),
        .milestone(.recovery, .started),
        .milestone(.recovery, .completed),
        .milestone(.validation, .started),
        .milestone(.validation, .completed),
      ]
    )
  }

  private func makePreflightingSession() throws -> SessionContext {
    let helper = FakeRecoveryHelperClient()
    let session = RecoverySession(
      helperClient: helper,
      destinationEncryptionValidator: { _ in syntheticDestinationIdentity }
    )
    let root = try trackedDirectory()
    let backup = root.appendingPathComponent("backup", isDirectory: true)
    let destination = root.appendingPathComponent("destination", isDirectory: true)
    try FileManager.default.createDirectory(at: backup, withIntermediateDirectories: false)
    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: false)
    try TestFixtures.setMode(0o700, at: backup)
    try TestFixtures.setMode(0o700, at: destination)
    session.selectBackup(backup)
    session.selectDestinationParent(destination)
    expectEqual(helper.invocations.count, 1)
    guard case .preflighting = session.phase else {
      throw FakeError.unexpectedPhase
    }
    return SessionContext(session: session, helper: helper)
  }

  private func makeRunningSession() async throws -> SessionContext {
    let context = try makePreflightingSession()
    context.helper.send(try TestFixtures.preflightCompletionEvent(), finish: true)
    try await waitUntil { context.session.phase == .confirm(TestFixtures.preflight()) }
    context.session.startRecovery(password: "password", acknowledgeSensitiveOutput: true)
    guard case .running = context.session.phase else {
      throw FakeError.unexpectedPhase
    }
    return context
  }

  private func makeRunningSession(
    validationGate: ValidationGate,
    diagnostics: any RecoveryDiagnosticsSink = UnifiedRecoveryDiagnostics()
  ) async throws -> SessionContext {
    let helper = FakeRecoveryHelperClient()
    let session = RecoverySession(
      helperClient: helper,
      diagnostics: diagnostics,
      destinationEncryptionValidator: { _ in syntheticDestinationIdentity },
      recoveryOutputValidator: { summary, outputDirectory in
        try validationGate.validate(summary, beneath: outputDirectory)
      }
    )
    let root = try trackedDirectory()
    let backup = root.appendingPathComponent("backup", isDirectory: true)
    let destination = root.appendingPathComponent("destination", isDirectory: true)
    try makePrivateDirectory(backup)
    try makePrivateDirectory(destination)
    session.selectBackup(backup)
    session.selectDestinationParent(destination)
    helper.send(try TestFixtures.preflightCompletionEvent(), finish: true)
    try await waitUntil { session.phase == .confirm(TestFixtures.preflight()) }
    session.startRecovery(password: "password", acknowledgeSensitiveOutput: true)
    guard case .running = session.phase else {
      throw FakeError.unexpectedPhase
    }
    return SessionContext(session: session, helper: helper)
  }

  private func deliverFailure(
    code: String,
    eventType: String = "failed",
    to context: SessionContext
  ) async throws {
    let failure = RecoveryFailure(code: code, message: "Recovery stopped safely", retryable: true)
    context.helper.send(
      try TestFixtures.event(type: eventType, payload: failure),
      finish: true
    )
    try await waitUntil { context.session.phase == .failed(failure) }
  }

  private func trackedDirectory() throws -> URL {
    let directory = try FileManager.default.makeTestDirectory()
    temporaryDirectories.append(directory)
    return directory
  }

  private func makePrivateDirectory(_ url: URL) throws {
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    try TestFixtures.setMode(0o700, at: url)
  }

  private func waitUntil(
    attempts: Int = 2_000,
    condition: @MainActor () -> Bool
  ) async throws {
    for _ in 0..<attempts {
      if condition() {
        return
      }
      try await Task.sleep(for: .milliseconds(1))
    }
    throw FakeError.timeout
  }
}

private final class ValidationGate: @unchecked Sendable {
  private let lock = NSLock()
  private let releaseSemaphore = DispatchSemaphore(value: 0)
  private let terminalError: Error?
  private var started = false
  private var mainThread = true
  private var validatedOutputDirectory: URL?

  init(terminalError: Error? = nil) {
    self.terminalError = terminalError
  }

  var hasStarted: Bool {
    lock.withLock { started }
  }

  var ranOnMainThread: Bool {
    lock.withLock { mainThread }
  }

  var outputDirectory: URL? {
    lock.withLock { validatedOutputDirectory }
  }

  func validate(_ summary: RecoverySummary, beneath outputDirectory: URL) throws {
    _ = summary
    lock.withLock {
      started = true
      mainThread = Thread.isMainThread
      validatedOutputDirectory = outputDirectory
    }
    while releaseSemaphore.wait(timeout: .now() + .milliseconds(5)) == .timedOut {
      try Task.checkCancellation()
    }
    try Task.checkCancellation()
    if let terminalError {
      throw terminalError
    }
  }

  func release() {
    releaseSemaphore.signal()
  }
}

@MainActor
private final class FakeRecoveryHelperClient: RecoveryHelperClient {
  struct Invocation {
    let request: RecoveryRequest
    let secret: Data?
  }

  private var continuation: AsyncThrowingStream<HelperEvent, Error>.Continuation?
  private(set) var invocations: [Invocation] = []
  private(set) var cancelCount = 0

  func events(
    for request: RecoveryRequest,
    secret: Data?
  ) throws -> AsyncThrowingStream<HelperEvent, Error> {
    let pair = AsyncThrowingStream<HelperEvent, Error>.makeStream(bufferingPolicy: .unbounded)
    continuation = pair.continuation
    invocations.append(Invocation(request: request, secret: secret))
    return pair.stream
  }

  func cancel() {
    cancelCount += 1
  }

  func send(_ event: HelperEvent, finish: Bool = false) {
    continuation?.yield(event)
    if finish {
      continuation?.finish()
      continuation = nil
    }
  }

  func finish(throwing error: Error) {
    continuation?.finish(throwing: error)
    continuation = nil
  }
}

private struct SessionContext {
  let session: RecoverySession
  let helper: FakeRecoveryHelperClient
}

private enum FakeError: Error {
  case communication
  case timeout
  case unexpectedPhase
}

@MainActor
private final class RecordingRecoveryDiagnostics: RecoveryDiagnosticsSink {
  private(set) var events: [RecoveryDiagnosticEvent] = []

  func record(_ event: RecoveryDiagnosticEvent) {
    events.append(event)
  }
}
