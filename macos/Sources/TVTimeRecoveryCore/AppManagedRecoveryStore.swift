import Darwin
import Foundation

@MainActor
public final class AppManagedRecoveryStore {
  private let rootURL: URL
  private let trustedAnchorURL: URL

  public convenience init(fileManager: FileManager = .default) {
    let applicationSupport = fileManager.urls(
      for: .applicationSupportDirectory,
      in: .userDomainMask
    )[0]
    self.init(
      rootURL:
        applicationSupport
        .appendingPathComponent("TV Time Backup Extractor", isDirectory: true)
        .appendingPathComponent("Recoveries", isDirectory: true),
      trustedAnchorURL:
        applicationSupport
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    )
  }

  init(rootURL: URL, trustedAnchorURL: URL) {
    self.rootURL = rootURL.standardizedFileURL
    self.trustedAnchorURL = trustedAnchorURL.standardizedFileURL
  }

  public func prepareDestination() throws -> URL {
    try createDirectoryTreeWithoutFollowingLinks()
    _ = try validateDestination(rootURL)
    return rootURL
  }

  public func existingDestination() throws -> URL? {
    var metadata = stat()
    let status = rootURL.path.withCString { Darwin.lstat($0, &metadata) }
    if status != 0, errno == ENOENT {
      return nil
    }
    guard status == 0, metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
      throw AppManagedRecoveryStoreError.invalidDirectory
    }
    _ = try validateDestination(rootURL)
    return rootURL
  }

  public func validateDestination(_ candidate: URL) throws -> DestinationDirectoryIdentity {
    guard candidate.standardizedFileURL == rootURL else {
      throw AppManagedRecoveryStoreError.destinationChanged
    }
    return try EncryptedDestinationValidator.requirePrivateLocalDestination(at: rootURL)
  }

  private func createDirectoryTreeWithoutFollowingLinks() throws {
    guard let components = relativeComponents(of: rootURL, beneath: trustedAnchorURL) else {
      throw AppManagedRecoveryStoreError.destinationChanged
    }
    let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    var current = trustedAnchorURL.path.withCString { Darwin.open($0, flags) }
    guard current >= 0 else {
      throw AppManagedRecoveryStoreError.invalidDirectory
    }
    defer { Darwin.close(current) }

    for component in components {
      var next = component.withCString { Darwin.openat(current, $0, flags) }
      if next < 0, errno == ENOENT {
        let created = component.withCString { Darwin.mkdirat(current, $0, 0o700) }
        guard created == 0 || errno == EEXIST else {
          throw AppManagedRecoveryStoreError.invalidDirectory
        }
        next = component.withCString { Darwin.openat(current, $0, flags) }
      }
      guard next >= 0 else {
        throw AppManagedRecoveryStoreError.invalidDirectory
      }
      Darwin.close(current)
      current = next
    }
    guard Darwin.fchmod(current, 0o700) == 0 else {
      throw AppManagedRecoveryStoreError.invalidDirectory
    }
  }

  private func relativeComponents(of destination: URL, beneath anchor: URL) -> [String]? {
    let destinationPath = destination.standardizedFileURL.path
    let anchorPath = anchor.standardizedFileURL.path
    guard destinationPath.hasPrefix(anchorPath + "/") else { return nil }
    return destinationPath.dropFirst(anchorPath.count + 1).split(separator: "/").map(String.init)
  }
}

enum AppManagedRecoveryStoreError: LocalizedError {
  case destinationChanged
  case invalidDirectory

  var errorDescription: String? {
    switch self {
    case .destinationChanged:
      "The private app-managed recovery location changed. Start again before recovering data."
    case .invalidDirectory:
      "The private app-managed recovery location is not a safe regular directory."
    }
  }
}
