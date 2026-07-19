import Foundation

public enum AccountHomeDirectoryResolver {
  public static func requireLocalAccountHome(_ candidate: URL?) throws -> URL {
    guard let candidate else {
      throw AccountHomeDirectoryError.unavailable
    }
    let home = candidate.standardizedFileURL
    guard
      home.isFileURL,
      home.path.hasPrefix("/"),
      home.path != "/",
      !home.pathComponents.contains("..")
    else {
      throw AccountHomeDirectoryError.unavailable
    }
    let values: URLResourceValues
    do {
      values = try home.resourceValues(forKeys: [.volumeIsLocalKey])
    } catch {
      throw AccountHomeDirectoryError.unavailable
    }
    guard values.volumeIsLocal == true else {
      throw AccountHomeDirectoryError.unavailable
    }
    return home
  }
}

public enum AccountHomeDirectoryError: LocalizedError, Equatable, Sendable {
  case unavailable

  public var errorDescription: String? {
    "The app could not locate this Mac account’s local home folder. In Finder, use your device’s Manage Backups → Show in Finder command, then choose that individual backup folder."
  }
}
