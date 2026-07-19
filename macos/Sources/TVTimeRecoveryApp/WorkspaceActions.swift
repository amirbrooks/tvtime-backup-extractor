import AppKit
import Foundation
import TVTimeRecoveryCore

@MainActor
final class WorkspaceActions {
  func openReport(_ report: URL, within output: URL) throws {
    try validate(report, within: output, expectedDirectory: false)
    guard NSWorkspace.shared.open(report) else {
      throw WorkspaceActionError.openFailed
    }
  }

  func reveal(_ item: URL, within output: URL) throws {
    try validate(item, within: output, expectedDirectory: true)
    NSWorkspace.shared.activateFileViewerSelecting([item])
  }

  func revealOutput(_ output: URL) throws {
    let root = output.standardizedFileURL
    _ = try EncryptedDestinationValidator.requirePrivateLocalDestination(at: root)
    try validateNoSymbolicLinkAncestry(root)
    let values = try root.resourceValues(forKeys: [
      .isDirectoryKey,
      .isSymbolicLinkKey,
    ])
    guard values.isDirectory == true, values.isSymbolicLink != true else {
      throw WorkspaceActionError.missingArtifact
    }
    NSWorkspace.shared.activateFileViewerSelecting([root])
  }

  private func validateNoSymbolicLinkAncestry(_ url: URL) throws {
    var current = URL(fileURLWithPath: "/", isDirectory: true)
    for component in url.standardizedFileURL.pathComponents.dropFirst() {
      current.appendPathComponent(component, isDirectory: true)
      let values = try current.resourceValues(forKeys: [.isSymbolicLinkKey])
      guard values.isSymbolicLink != true else {
        throw WorkspaceActionError.unsafeArtifact
      }
    }
  }

  private func validate(
    _ item: URL,
    within output: URL,
    expectedDirectory: Bool
  ) throws {
    let root = output.standardizedFileURL
    let candidate = item.standardizedFileURL
    let rootValues = try root.resourceValues(forKeys: [
      .isDirectoryKey,
      .isSymbolicLinkKey,
    ])
    guard
      root.isFileURL,
      candidate.isFileURL,
      rootValues.isDirectory == true,
      rootValues.isSymbolicLink != true,
      root.resolvingSymlinksInPath().standardizedFileURL.path == root.path,
      candidate.path.hasPrefix(root.path + "/")
    else {
      throw WorkspaceActionError.unsafeArtifact
    }

    let relative = candidate.path.dropFirst(root.path.count + 1)
    let components = relative.split(separator: "/", omittingEmptySubsequences: false)
    guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
    else {
      throw WorkspaceActionError.unsafeArtifact
    }

    var current = root
    for component in components {
      current.appendPathComponent(String(component))
      let values = try current.resourceValues(forKeys: [
        .isDirectoryKey,
        .isRegularFileKey,
        .isSymbolicLinkKey,
      ])
      guard values.isSymbolicLink != true else {
        throw WorkspaceActionError.unsafeArtifact
      }
    }

    let values = try candidate.resourceValues(forKeys: [
      .isDirectoryKey,
      .isRegularFileKey,
    ])
    let matches =
      expectedDirectory
      ? values.isDirectory == true
      : values.isRegularFile == true
    guard matches else {
      throw WorkspaceActionError.missingArtifact
    }
  }
}

private enum WorkspaceActionError: LocalizedError {
  case unsafeArtifact
  case missingArtifact
  case openFailed

  var errorDescription: String? {
    switch self {
    case .unsafeArtifact:
      "The recovered artifact did not pass the local path safety check."
    case .missingArtifact:
      "The expected recovered artifact is unavailable."
    case .openFailed:
      "macOS could not open the recovered report."
    }
  }
}
