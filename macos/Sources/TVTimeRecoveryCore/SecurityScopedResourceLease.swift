import Foundation

@MainActor
public final class SecurityScopedResourceLease {
  public let url: URL
  private var didStartAccess = false

  public init(url: URL) {
    self.url = url
    didStartAccess = url.startAccessingSecurityScopedResource()
  }

  public func stop() {
    guard didStartAccess else {
      return
    }
    url.stopAccessingSecurityScopedResource()
    didStartAccess = false
  }

  deinit {
    if didStartAccess {
      url.stopAccessingSecurityScopedResource()
    }
  }
}
