import SwiftUI
import TVTimeRecoveryCore

@MainActor
struct RecoveryRootView: View {
  let session: RecoverySession
  let folderPicker: FolderPicker
  let workspaceActions: WorkspaceActions
  let recoveryStore: AppManagedRecoveryStore
  let diagnostics: any RecoveryDiagnosticsSink

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
      case .failed(let failure):
        RecoveryErrorView(
          failure: failure,
          onPrimaryAction: session.recoverFromFailure,
          onStartOver: session.returnToBackupSelection,
          canRevealOutput: hasExistingOutput,
          onRevealOutput: revealOutput
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
    BackupStepView {
      try await folderPicker.chooseBackup()
    } onSelected: { url in
      do {
        let destination = try recoveryStore.prepareDestination()
        diagnostics.record(.milestone(.preflight, .privateStoragePrepared))
        session.selectBackup(url, appManagedDestinationParent: destination)
      } catch {
        diagnostics.record(.failure(.preflight, .privateStorageUnavailable))
        throw error
      }
    } onShowRecoveries: {
      do {
        guard let destination = try recoveryStore.existingDestination() else {
          throw RootActionError.missingArtifact
        }
        try workspaceActions.revealOutput(destination)
      } catch {
        diagnostics.record(.failure(.outputAccess, .outputUnavailable))
        throw error
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

private enum RootActionError: LocalizedError {
  case missingArtifact

  var errorDescription: String? {
    "The expected private recovery output is unavailable."
  }
}
