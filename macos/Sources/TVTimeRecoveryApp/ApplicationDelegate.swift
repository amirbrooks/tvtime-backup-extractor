import AppKit
import TVTimeRecoveryCore

@MainActor
final class ApplicationDelegate: NSObject, NSApplicationDelegate {
  let environment = AppEnvironment()

  private var terminationPending = false
  private var terminationTask: Task<Void, Never>?

  func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    guard environment.session.phase.isBusy else {
      return .terminateNow
    }
    guard !terminationPending else {
      return .terminateLater
    }

    terminationPending = true
    environment.session.requestCancellation(origin: .applicationQuit) {
      [weak self, weak sender] confirmed in
      guard let self, let sender else {
        return
      }
      if confirmed {
        waitForSafeTermination(sender)
        return
      }
      terminationPending = false
      terminationTask = nil
      sender.reply(toApplicationShouldTerminate: false)
    }
    return .terminateLater
  }

  private func waitForSafeTermination(_ sender: NSApplication) {
    terminationTask?.cancel()
    terminationTask = Task { @MainActor [weak self, weak sender] in
      guard let self else {
        sender?.reply(toApplicationShouldTerminate: true)
        return
      }
      while environment.session.phase.isBusy {
        try? await Task.sleep(for: .milliseconds(100))
        guard !Task.isCancelled else {
          return
        }
      }
      terminationPending = false
      terminationTask = nil
      sender?.reply(toApplicationShouldTerminate: true)
    }
  }
}
