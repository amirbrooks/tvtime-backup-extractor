import Observation
import TVTimeRecoveryCore

@MainActor
@Observable
final class AppEnvironment {
  let diagnostics: UnifiedRecoveryDiagnostics
  let helperClient: HelperProcessClient
  let session: RecoverySession
  let folderPicker: FolderPicker
  let workspaceActions: WorkspaceActions
  let recoveryStore: AppManagedRecoveryStore

  init() {
    let diagnostics = UnifiedRecoveryDiagnostics()
    let helperClient = HelperProcessClient()
    let recoveryStore = AppManagedRecoveryStore()
    self.diagnostics = diagnostics
    self.helperClient = helperClient
    self.recoveryStore = recoveryStore
    session = RecoverySession(
      helperClient: helperClient,
      diagnostics: diagnostics,
      destinationEncryptionValidator: recoveryStore.validateDestination
    )
    folderPicker = FolderPicker(diagnostics: diagnostics)
    workspaceActions = WorkspaceActions()
    diagnostics.record(.milestone(.app, .appLaunched))
  }
}
