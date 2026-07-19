import Darwin
import Foundation
import Testing

@testable import TVTimeRecoveryCore

@Suite
@MainActor
struct AppManagedRecoveryStoreTests {
  @Test
  func testUsesRealAccountHomeInsteadOfSandboxContainerHome() throws {
    let root = try makeStableStoreTestDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let accountHome = root.appendingPathComponent("account-home", isDirectory: true)
    let containerHome = root.appendingPathComponent("container-home", isDirectory: true)
    try FileManager.default.createDirectory(at: accountHome, withIntermediateDirectories: false)
    try FileManager.default.createDirectory(at: containerHome, withIntermediateDirectories: false)

    let resolved = try AccountHomeDirectoryResolver.requireLocalAccountHome(accountHome)

    expectEqual(resolved, accountHome.standardizedFileURL)
    expectNotEqual(resolved, containerHome.standardizedFileURL)
  }

  @Test
  func testAccountHomeFailsClosedWhenUnavailable() {
    expectThrowsError(try AccountHomeDirectoryResolver.requireLocalAccountHome(nil)) { error in
      expectEqual(error as? AccountHomeDirectoryError, .unavailable)
    }
  }

  @Test
  func testStoreCreatesOwnerOnlyRootAndSupportsRepeatedPreparation() throws {
    let temporaryRoot = try makeStableStoreTestDirectory()
    defer { try? FileManager.default.removeItem(at: temporaryRoot) }
    let root =
      temporaryRoot
      .appendingPathComponent("Application Support", isDirectory: true)
      .appendingPathComponent("TV Time Backup Extractor", isDirectory: true)
      .appendingPathComponent("Recoveries", isDirectory: true)
    let store = AppManagedRecoveryStore(rootURL: root, trustedAnchorURL: temporaryRoot)

    let first = try store.prepareDestination()
    let second = try store.prepareDestination()

    expectEqual(first, root.standardizedFileURL)
    expectEqual(second, first)
    var metadata = stat()
    expectEqual(Darwin.lstat(first.path, &metadata), 0)
    expectEqual(metadata.st_mode & 0o777, 0o700)
    let identity = try store.validateDestination(first)
    expectTrue(identity.inode > 0)
  }

  @Test
  func testStoreRejectsEveryDirectoryExceptItsExactRoot() throws {
    let temporaryRoot = try makeStableStoreTestDirectory()
    defer { try? FileManager.default.removeItem(at: temporaryRoot) }
    let root = temporaryRoot.appendingPathComponent("Recoveries", isDirectory: true)
    let other = temporaryRoot.appendingPathComponent("Other", isDirectory: true)
    let store = AppManagedRecoveryStore(rootURL: root, trustedAnchorURL: temporaryRoot)
    _ = try store.prepareDestination()
    try FileManager.default.createDirectory(at: other, withIntermediateDirectories: false)

    expectThrowsError(try store.validateDestination(other)) { error in
      guard case .destinationChanged = error as? AppManagedRecoveryStoreError else {
        Issue.record("Expected destinationChanged, received \(error)")
        return
      }
    }
  }

  @Test
  func testStoreRejectsSymbolicLinkAncestry() throws {
    let temporaryRoot = try makeStableStoreTestDirectory()
    defer { try? FileManager.default.removeItem(at: temporaryRoot) }
    let actual = temporaryRoot.appendingPathComponent("actual", isDirectory: true)
    let linked = temporaryRoot.appendingPathComponent("linked", isDirectory: true)
    try FileManager.default.createDirectory(at: actual, withIntermediateDirectories: false)
    try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: actual)
    let store = AppManagedRecoveryStore(
      rootURL: linked.appendingPathComponent("Recoveries", isDirectory: true),
      trustedAnchorURL: temporaryRoot
    )

    expectThrowsError(try store.prepareDestination())
    expectFalse(
      FileManager.default.fileExists(
        atPath: actual.appendingPathComponent("Recoveries", isDirectory: true).path
      )
    )
  }
}

private func makeStableStoreTestDirectory() throws -> URL {
  let packageRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let root =
    packageRoot
    .appendingPathComponent(".build", isDirectory: true)
    .appendingPathComponent("app-managed-store-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  return root
}
