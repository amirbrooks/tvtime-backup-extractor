import Foundation
import Testing

@testable import TVTimeRecoveryCore

@Suite
struct EncryptedDestinationValidatorTests {
  @Test
  func testRequiresAnAffirmativeMacOSEncryptionResult() {
    expectNoThrow(try EncryptedDestinationValidator.requireConfirmedEncryption(true))

    for value in [false, nil] as [Bool?] {
      expectThrowsError(
        try EncryptedDestinationValidator.requireConfirmedEncryption(value)
      ) { error in
        expectEqual(
          error as? EncryptedDestinationValidationError,
          .encryptionNotConfirmed
        )
      }
    }
  }

  @Test
  func testRequiresEncryptedLocalNonUbiquitousStorage() {
    expectNoThrow(
      try EncryptedDestinationValidator.requireConfirmedStorage(
        encrypted: true,
        local: true,
        ubiquitous: false
      )
    )

    for value in [false, nil] as [Bool?] {
      expectThrowsError(
        try EncryptedDestinationValidator.requireConfirmedStorage(
          encrypted: true,
          local: value,
          ubiquitous: false
        )
      ) { error in
        expectEqual(
          error as? EncryptedDestinationValidationError,
          .localStorageNotConfirmed
        )
      }
    }
    for value in [true, nil] as [Bool?] {
      expectThrowsError(
        try EncryptedDestinationValidator.requireConfirmedStorage(
          encrypted: true,
          local: true,
          ubiquitous: value
        )
      ) { error in
        expectEqual(error as? EncryptedDestinationValidationError, .cloudOrSharedLocation)
      }
    }
  }

  @Test
  func testAcceptsPrivateLocalAppManagedDirectoryWithoutVolumeEncryption() throws {
    let packageRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let root =
      packageRoot
      .appendingPathComponent(".build", isDirectory: true)
      .appendingPathComponent("app-managed-validator-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let destination = root.appendingPathComponent("Recoveries", isDirectory: true)
    try FileManager.default.createDirectory(
      at: destination,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )

    let identity = try EncryptedDestinationValidator.requirePrivateLocalDestination(
      at: destination
    )

    expectTrue(identity.inode > 0)
  }

  @Test
  func testRecognizesEncryptionAtTheMountedDiskImageLayer() throws {
    let encryptedMount = "/Volumes/Synthetic Protected Recovery"
    let info: [String: Any] = [
      "images": [
        [
          "image-encrypted": true,
          "image-path": "/Users/example/Synthetic.sparsebundle",
          "system-entities": [["mount-point": encryptedMount]],
        ],
        [
          "image-encrypted": false,
          "image-path": "/Users/example/Unprotected.dmg",
          "system-entities": [["mount-point": "/Volumes/Synthetic Unprotected"]],
        ],
      ]
    ]
    let data = try PropertyListSerialization.data(
      fromPropertyList: info,
      format: .binary,
      options: 0
    )

    let protectedResult = try EncryptedDestinationValidator.isInsideMountedEncryptedDiskImage(
      URL(fileURLWithPath: encryptedMount + "/Reports", isDirectory: true),
      diskImageInfo: data
    )
    let unprotectedResult = try EncryptedDestinationValidator.isInsideMountedEncryptedDiskImage(
      URL(fileURLWithPath: "/Volumes/Synthetic Unprotected/Reports", isDirectory: true),
      diskImageInfo: data
    )
    expectTrue(protectedResult)
    expectFalse(unprotectedResult)
  }

  @Test
  func testRejectsKnownCloudAndSharedAncestry() {
    let home = URL(fileURLWithPath: "/Users/example", isDirectory: true)
    let unsafe = [
      "/Users/example/Library/CloudStorage/Provider/Recovery",
      "/Users/example/Library/Mobile Documents/com~apple~CloudDocs/Recovery",
      "/Users/example/Library/Application Support/FileProvider/Recovery",
      "/Users/example/OneDrive - Example/Recovery",
      "/Users/example/Dropbox/Recovery",
      "/Users/example/Public/Recovery",
      "/Users/Shared/Recovery",
      "/Network/Server/Recovery",
    ]
    for path in unsafe {
      expectTrue(
        EncryptedDestinationValidator.isKnownSyncedOrSharedPath(
          URL(fileURLWithPath: path, isDirectory: true),
          homeDirectory: home,
          environment: [:]
        )
      )
    }
    expectFalse(
      EncryptedDestinationValidator.isKnownSyncedOrSharedPath(
        URL(fileURLWithPath: "/Users/example/Documents/Private Recovery", isDirectory: true),
        homeDirectory: home,
        environment: [:]
      )
    )
  }

  @Test
  func testStableIdentityCheckRejectsDirectorySubstitution() throws {
    let root = try FileManager.default.makeTestDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let destination = root.appendingPathComponent("destination", isDirectory: true)
    let moved = root.appendingPathComponent("moved", isDirectory: true)
    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: false)

    expectThrowsError(
      try EncryptedDestinationValidator.requireStableDirectoryIdentity(at: destination) {
        try FileManager.default.moveItem(at: destination, to: moved)
        try FileManager.default.createDirectory(
          at: destination,
          withIntermediateDirectories: false
        )
      }
    ) { error in
      expectEqual(
        error as? EncryptedDestinationValidationError,
        .identityNotConfirmed
      )
    }
  }
}
