import AppKit
import Foundation
import TVTimeRecoveryCore

@MainActor
final class FolderPicker {
  private let diagnostics: any RecoveryDiagnosticsSink

  init(diagnostics: any RecoveryDiagnosticsSink) {
    self.diagnostics = diagnostics
  }

  func chooseBackup() async throws -> URL? {
    diagnostics.record(.milestone(.backupPicker, .pickerPresented))
    let accountHome = try? AccountHomeDirectoryResolver.requireLocalAccountHome(
      FileManager.default.homeDirectory(forUser: NSUserName())
    )
    guard
      let selected = await chooseDirectory(
        title: "Choose an Encrypted iPhone or iPad Backup",
        message:
          "If one backup is present, choose this folder. If several appear, open the backup you want first.",
        prompt: "Choose Backup",
        canCreateDirectories: false,
        preferredInitialDirectory: accountHome.map(standardBackupPickerDirectory),
        fallbackInitialDirectory: accountHome
          ?? URL(fileURLWithPath: "/Users", isDirectory: true)
      )
    else {
      diagnostics.record(.milestone(.backupPicker, .pickerCancelled))
      return nil
    }
    do {
      try validateDirectory(selected)
      return try resolveSelectedBackup(selected)
    } catch {
      diagnostics.record(.failure(.backupPicker, diagnosticFailure(for: error)))
      throw error
    }
  }

  private func chooseDirectory(
    title: String,
    message: String,
    prompt: String,
    canCreateDirectories: Bool,
    preferredInitialDirectory: URL?,
    fallbackInitialDirectory: URL
  ) async -> URL? {
    let panel = NSOpenPanel()
    panel.title = title
    panel.message = message
    panel.prompt = prompt
    panel.canChooseFiles = false
    panel.canChooseDirectories = true
    panel.allowsMultipleSelection = false
    panel.canCreateDirectories = canCreateDirectories
    panel.resolvesAliases = true
    panel.directoryURL = fallbackInitialDirectory
    if let preferredInitialDirectory {
      // Let the system-owned panel resolve sandbox-restricted locations. Pre-reading
      // them from the app can fail even though the user can grant access here.
      panel.directoryURL = preferredInitialDirectory
    }
    return await withCheckedContinuation { continuation in
      panel.begin { response in
        continuation.resume(returning: response == .OK ? panel.url : nil)
      }
    }
  }

  private func standardBackupPickerDirectory(accountHome: URL) -> URL {
    accountHome
      .appendingPathComponent("Library", isDirectory: true)
      .appendingPathComponent("Application Support", isDirectory: true)
      .appendingPathComponent("MobileSync", isDirectory: true)
      .appendingPathComponent("Backup", isDirectory: true)
  }

  private func validateDirectory(_ url: URL) throws {
    let values: URLResourceValues
    do {
      values = try url.resourceValues(forKeys: [
        .isDirectoryKey,
        .isSymbolicLinkKey,
      ])
    } catch {
      throw FolderPickerError.unreadableDirectory
    }
    guard values.isDirectory == true, values.isSymbolicLink != true else {
      throw FolderPickerError.invalidDirectory
    }
  }

  private func resolveSelectedBackup(_ selected: URL) throws -> URL {
    let candidate = selected.standardizedFileURL
    if isIndividualBackup(candidate) {
      return candidate
    }

    let children: [URL]
    do {
      children = try FileManager.default.contentsOfDirectory(
        at: candidate,
        includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
        options: [.skipsHiddenFiles]
      )
    } catch {
      throw FolderPickerError.invalidBackup
    }
    let backups = children.filter(isIndividualBackup)
    guard backups.count == 1 else {
      if backups.count > 1 {
        throw FolderPickerError.multipleBackups
      }
      throw FolderPickerError.invalidBackup
    }
    return backups[0].standardizedFileURL
  }

  private func isIndividualBackup(_ candidate: URL) -> Bool {
    guard
      let directoryValues = try? candidate.resourceValues(forKeys: [
        .isDirectoryKey,
        .isSymbolicLinkKey,
      ]),
      directoryValues.isDirectory == true,
      directoryValues.isSymbolicLink != true
    else {
      return false
    }
    for name in ["Manifest.plist", "Manifest.db"] {
      let required = candidate.appendingPathComponent(name, isDirectory: false)
      guard
        let values = try? required.resourceValues(forKeys: [
          .isRegularFileKey,
          .isSymbolicLinkKey,
        ]),
        values.isRegularFile == true,
        values.isSymbolicLink != true
      else {
        return false
      }
    }
    return true
  }

  private func diagnosticFailure(for error: Error) -> RecoveryDiagnosticFailure {
    guard let pickerError = error as? FolderPickerError else {
      return .unrecognizedFailure
    }
    switch pickerError {
    case .invalidBackup:
      return .pickerInvalidBackup
    case .multipleBackups:
      return .pickerMultipleBackups
    case .invalidDirectory:
      return .pickerInvalidDirectory
    case .unreadableDirectory:
      return .pickerUnreadableDirectory
    }
  }
}

private enum FolderPickerError: LocalizedError {
  case invalidBackup
  case multipleBackups
  case invalidDirectory
  case unreadableDirectory

  var errorDescription: String? {
    switch self {
    case .invalidBackup:
      "That folder is not an individual completed local backup. Choose the folder containing regular Manifest.plist and Manifest.db files."
    case .multipleBackups:
      "More than one completed backup was found. Open the backup you want, then choose that folder. Finder’s Manage Backups → Show in Finder can identify it."
    case .invalidDirectory:
      "The selected item is not a safe regular directory."
    case .unreadableDirectory:
      "macOS could not inspect that folder safely. Choose another regular local folder."
    }
  }
}
