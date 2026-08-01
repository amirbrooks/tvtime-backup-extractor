import SwiftUI
import TVTimeRecoveryCore

@MainActor
struct RecoveryRootView: View {
  let session: RecoverySession
  let folderPicker: FolderPicker
  let workspaceActions: WorkspaceActions
  let recoveryStore: AppManagedRecoveryStore
  let diagnostics: UnifiedRecoveryDiagnostics
  @State private var selectedSource = RecoverySourceChoice.iosBackup

  var body: some View {
    Group {
      switch session.phase {
      case .chooseBackup:
        backupStep
      case .chooseDestination:
        backupStep
      case .preflighting(let progress):
        RecoveryProgressView(
          title: "Checking the backup",
          progress: progress,
          cancelTitle: "Cancel Check",
          onCancel: session.cancel
        )
      case .confirm(let summary):
        ConfirmationStepView(
          summary: summary,
          destinationIdentity: "Private storage managed by this app",
          outputFolderName: session.outputDirectory?.lastPathComponent
            ?? "Fresh recovery folder",
          onStart: session.startRecovery,
          onBack: session.returnToBackupSelection
        )
      case .running(let progress):
        RecoveryProgressView(
          title: "Recovering TV Time data",
          progress: progress,
          cancelTitle: "Cancel Recovery",
          onCancel: session.cancel
        )
      case .validating(let progress):
        RecoveryProgressView(
          title: "Verifying the recovered package",
          progress: progress,
          cancelTitle: "Cancel Verification",
          onCancel: session.cancel
        )
      case .cancelling:
        CancellingView()
      case .completed(let summary):
        RecoveryResultView(
          summary: summary,
          hasVisualReport: session.visualReportURL != nil,
          hasPDFReport: session.pdfReportURL != nil,
          onOpenVisualReport: openVisualReport,
          onOpenPDFReport: openPDFReport,
          onOpenMarkdown: openMarkdown,
          onReveal: revealOutput,
          onStartAgain: session.returnToBackupSelection
        )
      case .acquisitionCompleted(let summary):
        RecoveryResultView(
          summary: summary,
          hasVisualReport: session.visualReportURL != nil,
          hasPDFReport: session.pdfReportURL != nil,
          onOpenVisualReport: openVisualReport,
          onOpenPDFReport: openPDFReport,
          onOpenMarkdown: openMarkdown,
          onReveal: revealOutput,
          onStartAgain: session.returnToBackupSelection
        )
      case .failed(let failure):
        RecoveryErrorView(
          failure: failure,
          troubleshootingReport: diagnostics.troubleshootingReport,
          onPrimaryAction: session.recoverFromFailure,
          onStartOver: session.returnToBackupSelection,
          canRevealOutput: hasExistingOutput,
          onRevealOutput: revealOutput,
          onCopyTroubleshootingReport: workspaceActions.copyTroubleshootingReport
        )
      }
    }
    .padding(32)
    .alert(
      cancellationPromptTitle,
      isPresented: cancellationPromptPresented
    ) {
      Button(isValidating ? "Continue Verification" : "Continue Recovery", role: .cancel) {
        session.continueRecovery()
      }
      .keyboardShortcut(.defaultAction)
      Button(cancellationConfirmTitle, role: .destructive) {
        session.confirmCancellation()
      }
    } message: {
      Text(
        "Cancelling preserves the current output for review, but it cannot be trusted as a "
          + "verified recovery package or reused. A future attempt must use a fresh output "
          + "folder."
      )
    }
  }

  private var backupStep: some View {
    VStack(spacing: 18) {
      Picker("Recovery source", selection: $selectedSource) {
        ForEach(RecoverySourceChoice.allCases) { choice in
          Text(choice.label).tag(choice)
        }
      }
      .pickerStyle(.segmented)
      .frame(maxWidth: 720)

      if selectedSource == .iosBackup {
        BackupStepView {
          diagnostics.beginAttempt()
          return try await folderPicker.chooseBackup()
        } onSelected: { url in
          diagnostics.record(.milestone(.backupPicker, .backupAccepted))
          do {
            let destination = try recoveryStore.prepareDestination()
            diagnostics.record(.milestone(.preflight, .privateStoragePrepared))
            session.selectBackup(url, appManagedDestinationParent: destination)
          } catch {
            diagnostics.record(.failure(.preflight, .privateStorageUnavailable))
            throw error
          }
        } onShowRecoveries: {
          diagnostics.beginAttempt()
          diagnostics.record(.milestone(.outputAccess, .requested))
          do {
            guard let destination = try recoveryStore.existingDestination() else {
              throw RootActionError.missingArtifact
            }
            try workspaceActions.revealOutput(destination)
          } catch {
            diagnostics.record(.failure(.outputAccess, .outputUnavailable))
            throw error
          }
        } troubleshootingReport: {
          diagnostics.troubleshootingReport
        } onCopyTroubleshootingReport: {
          try workspaceActions.copyTroubleshootingReport($0)
        }
      } else if let acquisitionKind = selectedSource.acquisitionKind {
        AcquisitionStepView(sourceKind: acquisitionKind) {
          diagnostics.beginAttempt()
          return try await folderPicker.chooseAcquisitionSource(kind: acquisitionKind)
        } onStart: { source, password, acknowledged in
          diagnostics.beginSourceAttempt()
          do {
            let destination = try recoveryStore.prepareDestination()
            diagnostics.record(.milestone(.recovery, .privateStoragePrepared))
            session.startAcquisition(
              sourceKind: acquisitionKind,
              sourceURL: source,
              appManagedDestinationParent: destination,
              sourcePassword: password,
              acknowledgeSensitiveOutput: acknowledged
            )
          } catch {
            diagnostics.record(.failure(.recovery, .privateStorageUnavailable))
            throw error
          }
        } troubleshootingReport: {
          diagnostics.troubleshootingReport
        } onCopyTroubleshootingReport: {
          try workspaceActions.copyTroubleshootingReport($0)
        }
        .id(acquisitionKind.rawValue)
      }
    }
  }

  private var cancellationPromptPresented: Binding<Bool> {
    Binding(
      get: { session.pendingCancellationPrompt != nil },
      set: { presented in
        if !presented, session.pendingCancellationPrompt != nil {
          session.continueRecovery()
        }
      }
    )
  }

  private var cancellationPromptTitle: String {
    let operation = isValidating ? "verification" : "recovery"
    return switch session.pendingCancellationPrompt?.origin {
    case .applicationQuit:
      "Cancel \(operation) and quit?"
    case .windowClose:
      "Cancel \(operation) and close this window?"
    case .cancelButton, nil:
      "Cancel \(operation)?"
    }
  }

  private var cancellationConfirmTitle: String {
    let operation = isValidating ? "Verification" : "Recovery"
    return switch session.pendingCancellationPrompt?.origin {
    case .applicationQuit:
      "Cancel \(operation) and Quit"
    case .windowClose:
      "Cancel \(operation) and Close"
    case .cancelButton, nil:
      "Cancel \(operation)"
    }
  }

  private var isValidating: Bool {
    if case .validating = session.phase {
      return true
    }
    return false
  }

  private func openVisualReport() throws {
    guard let report = session.visualReportURL, let output = session.outputDirectory else {
      throw RootActionError.missingArtifact
    }
    try workspaceActions.openReport(report, within: output)
  }

  private func openPDFReport() throws {
    guard let report = session.pdfReportURL, let output = session.outputDirectory else {
      throw RootActionError.missingArtifact
    }
    try workspaceActions.openReport(report, within: output)
  }

  private func openMarkdown() throws {
    guard let report = session.markdownReportURL, let output = session.outputDirectory else {
      throw RootActionError.missingArtifact
    }
    try workspaceActions.openReport(report, within: output)
  }

  private var hasExistingOutput: Bool {
    guard let output = session.outputDirectory else { return false }
    let values = try? output.resourceValues(forKeys: [
      .isDirectoryKey,
      .isSymbolicLinkKey,
    ])
    return values?.isDirectory == true && values?.isSymbolicLink != true
  }

  private func revealOutput() throws {
    guard let output = session.outputDirectory else {
      throw RootActionError.missingArtifact
    }
    try workspaceActions.revealOutput(output)
  }
}

private enum RecoverySourceChoice: String, CaseIterable, Identifiable {
  case iosBackup
  case androidBackup
  case androidSnapshot
  case officialExport

  var id: String { rawValue }

  var label: String {
    switch self {
    case .iosBackup: "iOS Backup"
    case .androidBackup: "Android Backup"
    case .androidSnapshot: "Android Snapshot"
    case .officialExport: "Official Export"
    }
  }

  var acquisitionKind: AcquisitionSourceKind? {
    switch self {
    case .iosBackup: nil
    case .androidBackup: .androidLegacyBackup
    case .androidSnapshot: .androidPreservedSnapshot
    case .officialExport: .tvTimeOfficialExport
    }
  }
}

private enum RootActionError: LocalizedError {
  case missingArtifact

  var errorDescription: String? {
    "The expected private recovery output is unavailable."
  }
}
