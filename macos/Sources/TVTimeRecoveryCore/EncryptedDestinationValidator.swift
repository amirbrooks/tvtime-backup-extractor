import Darwin
import Foundation

public enum EncryptedDestinationValidationError: LocalizedError, Equatable, Sendable {
  case encryptionNotConfirmed
  case localStorageNotConfirmed
  case cloudOrSharedLocation
  case identityNotConfirmed

  public var errorDescription: String? {
    switch self {
    case .encryptionNotConfirmed:
      "macOS could not confirm that this destination is protected by FileVault, an encrypted "
        + "volume, or an encrypted disk image."
    case .localStorageNotConfirmed:
      "macOS could not confirm that this destination is on a local volume. Choose private local "
        + "storage rather than a network or remote volume."
    case .cloudOrSharedLocation:
      "That location may be cloud-synced or shared. Choose a private local folder outside cloud "
        + "and shared storage."
    case .identityNotConfirmed:
      "The private output storage changed while macOS was checking it. Start over before recovery."
    }
  }
}

public enum EncryptedDestinationValidator {
  private static let homeSyncRootNames: Set<String> = [
    "box",
    "box sync",
    "creative cloud files",
    "dropbox",
    "google drive",
    "icloud drive",
    "mega",
    "onedrive",
    "pcloud drive",
    "public",
    "resilio sync",
    "sync.com",
  ]

  public static func requirePrivateEncryptedLocalDestination(at url: URL) throws
    -> DestinationDirectoryIdentity
  {
    let candidate = url.standardizedFileURL
    return try requireStableDirectoryIdentity(at: candidate) {
      try requireNoSymbolicLinkAncestry(candidate)
      if isKnownSyncedOrSharedPath(candidate) {
        throw EncryptedDestinationValidationError.cloudOrSharedLocation
      }
      let values: URLResourceValues
      do {
        values = try candidate.resourceValues(forKeys: [
          .volumeIsEncryptedKey,
          .volumeIsLocalKey,
        ])
      } catch {
        throw EncryptedDestinationValidationError.localStorageNotConfirmed
      }
      let encryptionConfirmed =
        values.volumeIsEncrypted == true
        || (try? isInsideMountedEncryptedDiskImage(candidate)) == true
      try requireConfirmedStorage(
        encrypted: encryptionConfirmed,
        local: values.volumeIsLocal,
        ubiquitous: FileManager.default.isUbiquitousItem(at: candidate)
      )
    }
  }

  public static func requirePrivateLocalDestination(at url: URL) throws
    -> DestinationDirectoryIdentity
  {
    let candidate = url.standardizedFileURL
    return try requireStableDirectoryIdentity(at: candidate) {
      try requireNoSymbolicLinkAncestry(candidate)
      if isKnownSyncedOrSharedPath(candidate) {
        throw EncryptedDestinationValidationError.cloudOrSharedLocation
      }
      let values: URLResourceValues
      do {
        values = try candidate.resourceValues(forKeys: [.volumeIsLocalKey])
      } catch {
        throw EncryptedDestinationValidationError.localStorageNotConfirmed
      }
      guard values.volumeIsLocal == true else {
        throw EncryptedDestinationValidationError.localStorageNotConfirmed
      }
      guard FileManager.default.isUbiquitousItem(at: candidate) == false else {
        throw EncryptedDestinationValidationError.cloudOrSharedLocation
      }
    }
  }

  public static func requireEncryptedVolume(at url: URL) throws {
    let candidate = url.standardizedFileURL
    let volumeEncrypted = try? candidate.resourceValues(forKeys: [.volumeIsEncryptedKey])
      .volumeIsEncrypted
    let diskImageEncrypted = (try? isInsideMountedEncryptedDiskImage(candidate)) == true
    try requireConfirmedEncryption(volumeEncrypted == true || diskImageEncrypted)
  }

  static func isInsideMountedEncryptedDiskImage(
    _ candidate: URL,
    diskImageInfo: Data? = nil
  ) throws -> Bool {
    let data = try diskImageInfo ?? mountedDiskImageInfo()
    let propertyList = try PropertyListSerialization.propertyList(from: data, format: nil)
    guard let root = propertyList as? [String: Any], let images = root["images"] as? [[String: Any]]
    else {
      return false
    }

    let candidatePath = candidate.standardizedFileURL.path
    for image in images where (image["image-encrypted"] as? Bool) == true {
      guard let entities = image["system-entities"] as? [[String: Any]] else {
        continue
      }
      for entity in entities {
        guard let mountPath = entity["mount-point"] as? String, !mountPath.isEmpty else {
          continue
        }
        let standardizedMount = URL(fileURLWithPath: mountPath, isDirectory: true)
          .standardizedFileURL
          .path
        if candidatePath == standardizedMount || candidatePath.hasPrefix(standardizedMount + "/") {
          return true
        }
      }
    }
    return false
  }

  private static func mountedDiskImageInfo() throws -> Data {
    let process = Process()
    let output = Pipe()
    let errors = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil", isDirectory: false)
    process.arguments = ["info", "-plist"]
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    _ = errors.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
      throw EncryptedDestinationValidationError.encryptionNotConfirmed
    }
    return data
  }

  static func requireConfirmedEncryption(_ value: Bool?) throws {
    guard value == true else {
      throw EncryptedDestinationValidationError.encryptionNotConfirmed
    }
  }

  static func requireConfirmedStorage(
    encrypted: Bool?,
    local: Bool?,
    ubiquitous: Bool?
  ) throws {
    try requireConfirmedEncryption(encrypted)
    guard local == true else {
      throw EncryptedDestinationValidationError.localStorageNotConfirmed
    }
    guard ubiquitous == false else {
      throw EncryptedDestinationValidationError.cloudOrSharedLocation
    }
  }

  static func requireStableDirectoryIdentity(
    at url: URL,
    validation: () throws -> Void
  ) throws -> DestinationDirectoryIdentity {
    let before = try directoryIdentity(at: url)
    try validation()
    let after = try directoryIdentity(at: url)
    guard before == after else {
      throw EncryptedDestinationValidationError.identityNotConfirmed
    }
    return before
  }

  static func directoryIdentity(at url: URL) throws -> DestinationDirectoryIdentity {
    guard url.isFileURL else {
      throw EncryptedDestinationValidationError.identityNotConfirmed
    }
    var metadata = stat()
    let status = url.standardizedFileURL.path.withCString { Darwin.lstat($0, &metadata) }
    guard
      status == 0,
      metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
      metadata.st_dev >= 0
    else {
      throw EncryptedDestinationValidationError.identityNotConfirmed
    }
    return DestinationDirectoryIdentity(
      device: UInt64(metadata.st_dev),
      inode: UInt64(metadata.st_ino)
    )
  }

  static func requireNoSymbolicLinkAncestry(_ url: URL) throws {
    guard url.isFileURL else {
      throw EncryptedDestinationValidationError.identityNotConfirmed
    }
    var current = URL(fileURLWithPath: "/", isDirectory: true)
    for component in url.standardizedFileURL.pathComponents.dropFirst() {
      current.appendPathComponent(component, isDirectory: true)
      var metadata = stat()
      let status = current.path.withCString { Darwin.lstat($0, &metadata) }
      guard status == 0, metadata.st_mode & mode_t(S_IFMT) != mode_t(S_IFLNK) else {
        throw EncryptedDestinationValidationError.identityNotConfirmed
      }
    }
  }

  static func isKnownSyncedOrSharedPath(
    _ url: URL,
    homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
    environment: [String: String] = ProcessInfo.processInfo.environment
  ) -> Bool {
    let candidate = url.standardizedFileURL
    let home = homeDirectory.standardizedFileURL
    if let parts = relativeComponents(of: candidate, beneath: home), !parts.isEmpty {
      let first = parts[0]
      if homeSyncRootNames.contains(first)
        || first.hasPrefix("onedrive - ")
        || first.hasPrefix("dropbox (")
        || first.hasPrefix("icloud drive (")
      {
        return true
      }
      if parts.count >= 2 {
        let prefix = Array(parts.prefix(2))
        if prefix == ["library", "cloudstorage"]
          || prefix == ["library", "fileprovider"]
          || prefix == ["library", "mobile documents"]
        {
          return true
        }
      }
      if parts.count >= 3,
        Array(parts.prefix(3)) == ["library", "application support", "fileprovider"]
      {
        return true
      }
    }

    for key in [
      "BOX_SYNC",
      "DROPBOX",
      "GOOGLE_DRIVE",
      "ICLOUD_DRIVE",
      "OneDrive",
      "OneDriveCommercial",
      "OneDriveConsumer",
      "PUBLIC",
    ] {
      guard let configured = environment[key], !configured.isEmpty else { continue }
      if isWithin(candidate, URL(fileURLWithPath: configured, isDirectory: true)) {
        return true
      }
    }
    return isWithin(candidate, URL(fileURLWithPath: "/Network", isDirectory: true))
      || isWithin(candidate, URL(fileURLWithPath: "/Users/Shared", isDirectory: true))
  }

  private static func relativeComponents(of candidate: URL, beneath root: URL) -> [String]? {
    let candidatePath = candidate.path.casefoldedPath
    let rootPath = root.path.casefoldedPath
    guard candidatePath == rootPath || candidatePath.hasPrefix(rootPath + "/") else {
      return nil
    }
    guard candidatePath != rootPath else { return [] }
    return candidatePath.dropFirst(rootPath.count + 1).split(separator: "/").map(String.init)
  }

  private static func isWithin(_ candidate: URL, _ root: URL) -> Bool {
    let candidatePath = candidate.standardizedFileURL.path.casefoldedPath
    let rootPath = root.standardizedFileURL.path.casefoldedPath
    return candidatePath == rootPath || candidatePath.hasPrefix(rootPath + "/")
  }
}

extension String {
  fileprivate var casefoldedPath: String {
    folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
  }
}
