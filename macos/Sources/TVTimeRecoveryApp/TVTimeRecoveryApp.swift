import SwiftUI
import TVTimeRecoveryCore

@main
@MainActor
struct TVTimeRecoveryApp: App {
  @NSApplicationDelegateAdaptor(ApplicationDelegate.self) private var appDelegate

  var body: some Scene {
    WindowGroup("TV Time Backup Extractor", id: "recovery") {
      RecoverySceneRoot(environment: appDelegate.environment)
    }
    .defaultSize(width: 760, height: 600)
    .commands {
      CommandGroup(replacing: .newItem) {}
    }
  }
}

@MainActor
private struct RecoverySceneRoot: View {
  let environment: AppEnvironment

  var body: some View {
    RecoveryRootView(
      session: environment.session,
      folderPicker: environment.folderPicker,
      workspaceActions: environment.workspaceActions,
      recoveryStore: environment.recoveryStore,
      diagnostics: environment.diagnostics
    )
    .frame(minWidth: 620, minHeight: 480)
    .background {
      WindowCloseGuard(
        allowsClose: !environment.session.phase.isBusy,
        requestClose: { decisionHandler in
          environment.session.requestCancellation(
            origin: .windowClose,
            decisionHandler: decisionHandler
          )
        }
      )
      .frame(width: 0, height: 0)
    }
  }
}
