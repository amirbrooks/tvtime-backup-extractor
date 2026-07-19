import Darwin
import Foundation
import Testing

@testable import TVTimeRecoveryCore

@Suite(.serialized)
@MainActor
struct HelperProcessClientTests {
  @Test
  func testCreatedPipeEndsAreCloseOnExec() throws {
    let pipe = try HelperProcessClient.makePipe()
    defer {
      Darwin.close(pipe.read)
      Darwin.close(pipe.write)
    }

    for descriptor in [pipe.read, pipe.write] {
      let flags = Darwin.fcntl(descriptor, F_GETFD)
      #expect(flags >= 0)
      #expect(flags & FD_CLOEXEC == FD_CLOEXEC)
    }
  }

  @Test
  func testParentDescriptorSetClosesEachOwnedDescriptorExactlyOnce() {
    var descriptors = HelperProcessClient.ParentDescriptorSet([7, nil, 9, 10])
    var closed: [Int32] = []

    descriptors.closeAll { descriptor in
      closed.append(descriptor)
      return 0
    }
    descriptors.closeAll { descriptor in
      closed.append(descriptor)
      return 0
    }

    #expect(closed == [7, 9, 10])
    #expect(descriptors.descriptors.isEmpty)
  }

  @Test
  func testTerminalEventBoundsAHelperThatKeepsItsEventStreamOpen() async throws {
    let packageRoot =
      URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let root =
      packageRoot
      .appendingPathComponent(".build", isDirectory: true)
      .appendingPathComponent("tvtime-helper-client-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let app = try makeSyntheticApp(at: root)
    let bundle = try #require(Bundle(url: app))
    let helperBundleURL =
      app
      .appendingPathComponent("Contents", isDirectory: true)
      .appendingPathComponent("Helpers", isDirectory: true)
      .appendingPathComponent("TVTimeHelper.bundle", isDirectory: true)
    let helperBundle = try #require(Bundle(url: helperBundleURL))
    let helperExecutable =
      helperBundleURL
      .appendingPathComponent("Contents", isDirectory: true)
      .appendingPathComponent("MacOS", isDirectory: true)
      .appendingPathComponent("tvtime-helper", isDirectory: false)
    #expect(helperBundle.bundleIdentifier == "com.amirbrooks.tvtime-backup-extractor.helper")
    #expect(helperBundle.bundleURL.standardizedFileURL == helperBundleURL.standardizedFileURL)
    #expect(helperBundle.executableURL?.standardizedFileURL == helperExecutable.standardizedFileURL)
    #expect(pathHasNoSymbolicLinks(helperExecutable))
    var isDirectory: ObjCBool = false
    #expect(
      FileManager.default.fileExists(atPath: helperExecutable.path, isDirectory: &isDirectory)
    )
    #expect(!isDirectory.boolValue)
    #expect(FileManager.default.isExecutableFile(atPath: helperExecutable.path))
    let values = try helperExecutable.resourceValues(
      forKeys: [.isRegularFileKey, .isSymbolicLinkKey]
    )
    #expect(values.isRegularFile == true)
    #expect(values.isSymbolicLink != true)
    let client = HelperProcessClient(bundle: bundle)
    let destinationIdentity = try directoryIdentity(at: root)
    let request = RecoveryRequest(
      action: .preflight,
      backupDirectory: root.appendingPathComponent("backup", isDirectory: true),
      outputDirectory: root.appendingPathComponent("output", isDirectory: true),
      destinationParentIdentity: destinationIdentity,
      acknowledgeSensitiveOutput: false
    )

    let started = ContinuousClock.now
    let stream = try client.events(for: request, secret: nil)
    var sawReady = false
    var sawCancellation = false
    for try await event in stream {
      switch event.body {
      case .ready:
        sawReady = true
      case .cancelled:
        sawCancellation = true
      case .progress, .preflightCompleted, .recoveryCompleted, .failed:
        break
      }
    }

    #expect(sawReady)
    #expect(sawCancellation)
    #expect(started.duration(to: .now) < .seconds(8))
  }

  @Test
  func testRecoveryMapsOnlyTheRequiredSecretAndDestinationDescriptors() async throws {
    let packageRoot =
      URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let root =
      packageRoot
      .appendingPathComponent(".build", isDirectory: true)
      .appendingPathComponent("tvtime-helper-recovery-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let app = try makeSyntheticApp(at: root, helperSource: syntheticRecoveryHelperSource)
    let bundle = try #require(Bundle(url: app))
    let destinationIdentity = try directoryIdentity(at: root)
    let request = RecoveryRequest(
      action: .recover,
      backupDirectory: root.appendingPathComponent("backup", isDirectory: true),
      outputDirectory: root.appendingPathComponent("output", isDirectory: true),
      destinationParentIdentity: destinationIdentity,
      acknowledgeSensitiveOutput: true,
      backupReceipt: TestFixtures.backupReceipt()
    )

    let client = HelperProcessClient(bundle: bundle)
    let stream = try client.events(
      for: request,
      secret: Data("synthetic-secret".utf8)
    )
    var sawReady = false
    var sawExpectedFailure = false
    for try await event in stream {
      switch event.body {
      case .ready:
        sawReady = true
      case .failed(let failure):
        sawExpectedFailure = failure.code == "recovery_failed"
      case .progress, .preflightCompleted, .recoveryCompleted, .cancelled:
        break
      }
    }

    #expect(sawReady)
    #expect(sawExpectedFailure)
  }

  @Test
  func testIdentityMismatchFailsBeforeSpawnWithoutLeakingDescriptors() throws {
    let packageRoot =
      URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let root =
      packageRoot
      .appendingPathComponent(".build", isDirectory: true)
      .appendingPathComponent(
        "tvtime-helper-client-mismatch-\(UUID().uuidString)",
        isDirectory: true
      )
    defer { try? FileManager.default.removeItem(at: root) }
    let app = try makeSyntheticApp(at: root)
    let bundle = try #require(Bundle(url: app))
    let actual = try directoryIdentity(at: root)
    let request = RecoveryRequest(
      action: .preflight,
      backupDirectory: root.appendingPathComponent("backup", isDirectory: true),
      outputDirectory: root.appendingPathComponent("output", isDirectory: true),
      destinationParentIdentity: DestinationDirectoryIdentity(
        device: actual.device,
        inode: actual.inode &+ 1
      ),
      acknowledgeSensitiveOutput: false
    )
    let client = HelperProcessClient(bundle: bundle)
    for _ in 0..<2 {
      do {
        _ = try client.events(for: request, secret: nil)
        Issue.record("Expected an identity mismatch to fail before helper launch")
      } catch let error as HelperClientError {
        guard case .destinationChanged = error else {
          Issue.record("Expected destinationChanged, received \(error)")
          return
        }
      }
    }
  }

  @Test
  func testDestinationParentRejectsSymlinkedAncestor() throws {
    let root = try FileManager.default.makeTestDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let actual = root.appendingPathComponent("actual", isDirectory: true)
    let linked = root.appendingPathComponent("linked", isDirectory: true)
    try FileManager.default.createDirectory(at: actual, withIntermediateDirectories: false)
    try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: actual)
    let identity = try directoryIdentity(at: actual)
    let request = RecoveryRequest(
      action: .preflight,
      backupDirectory: root.appendingPathComponent("backup", isDirectory: true),
      outputDirectory: linked.appendingPathComponent("output", isDirectory: true),
      destinationParentIdentity: identity,
      acknowledgeSensitiveOutput: false
    )

    expectThrowsError(try HelperProcessClient.openBoundDestinationParent(for: request)) { error in
      guard case .destinationChanged = error as? HelperClientError else {
        Issue.record("Expected destinationChanged, received \(error)")
        return
      }
    }
  }

  @Test
  func testDescriptorWalkCannotBeRedirectedByVisibleAncestorSubstitution() throws {
    let root = try FileManager.default.makeTestDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let visible = root.appendingPathComponent("visible", isDirectory: true)
    let original = root.appendingPathComponent("original", isDirectory: true)
    let alternate = root.appendingPathComponent("alternate", isDirectory: true)
    let destinationName = "destination"
    try FileManager.default.createDirectory(
      at: visible.appendingPathComponent(destinationName, isDirectory: true),
      withIntermediateDirectories: true
    )
    try FileManager.default.createDirectory(
      at: alternate.appendingPathComponent(destinationName, isDirectory: true),
      withIntermediateDirectories: true
    )
    let expected = try directoryIdentity(
      at: visible.appendingPathComponent(destinationName, isDirectory: true)
    )
    var substituted = false

    let opened = try HelperProcessClient.openDirectoryWithoutFollowingLinks(
      visible.appendingPathComponent(destinationName, isDirectory: true),
      trustedAnchor: root
    ) { openedURL in
      guard openedURL == visible, !substituted else { return }
      try? FileManager.default.moveItem(at: visible, to: original)
      try? FileManager.default.createSymbolicLink(at: visible, withDestinationURL: alternate)
      substituted = true
    }
    defer { Darwin.close(opened) }

    var metadata = stat()
    expectEqual(Darwin.fstat(opened, &metadata), 0)
    expectTrue(substituted)
    expectEqual(
      DestinationDirectoryIdentity(device: UInt64(metadata.st_dev), inode: UInt64(metadata.st_ino)),
      expected
    )
  }

  @Test
  func testPostSpawnControlWriteFailureClosesEveryParentDescriptor() throws {
    let packageRoot =
      URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let root =
      packageRoot
      .appendingPathComponent(".build", isDirectory: true)
      .appendingPathComponent(
        "tvtime-helper-client-write-failure-\(UUID().uuidString)",
        isDirectory: true
      )
    defer { try? FileManager.default.removeItem(at: root) }
    let app = try makeSyntheticApp(at: root, helperSource: "#!/bin/sh\nexit 0\n")
    let bundle = try #require(Bundle(url: app))
    let destinationIdentity = try directoryIdentity(at: root)
    let oversizedButValidFramePath = "/" + String(repeating: "a", count: 900_000)
    let request = RecoveryRequest(
      action: .preflight,
      backupDirectory: URL(fileURLWithPath: oversizedButValidFramePath),
      outputDirectory: root.appendingPathComponent("output", isDirectory: true),
      destinationParentIdentity: destinationIdentity,
      acknowledgeSensitiveOutput: false
    )
    let client = HelperProcessClient(bundle: bundle)
    for _ in 0..<2 {
      do {
        _ = try client.events(for: request, secret: nil)
        Issue.record("Expected the exited helper to reject the control frame")
      } catch let error as HelperClientError {
        guard case .communicationFailed = error else {
          Issue.record("Expected communicationFailed, received \(error)")
          return
        }
      }
    }
  }

  private func makeSyntheticApp(at root: URL, helperSource: String? = nil) throws -> URL {
    let app = root.appendingPathComponent("Synthetic.app", isDirectory: true)
    let appContents = app.appendingPathComponent("Contents", isDirectory: true)
    let appExecutable =
      appContents
      .appendingPathComponent("MacOS", isDirectory: true)
      .appendingPathComponent("SyntheticApp", isDirectory: false)
    let helperContents =
      appContents
      .appendingPathComponent("Helpers", isDirectory: true)
      .appendingPathComponent("TVTimeHelper.bundle", isDirectory: true)
      .appendingPathComponent("Contents", isDirectory: true)
    let helperExecutable =
      helperContents
      .appendingPathComponent("MacOS", isDirectory: true)
      .appendingPathComponent("tvtime-helper", isDirectory: false)

    try FileManager.default.createDirectory(
      at: appExecutable.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    try FileManager.default.createDirectory(
      at: helperExecutable.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    try writePropertyList(
      [
        "CFBundleExecutable": "SyntheticApp",
        "CFBundleIdentifier": "com.example.tvtime-helper-client-tests",
        "CFBundleName": "Synthetic",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
      ],
      to: appContents.appendingPathComponent("Info.plist")
    )
    try writePropertyList(
      [
        "CFBundleExecutable": "tvtime-helper",
        "CFBundleIdentifier": "com.amirbrooks.tvtime-backup-extractor.helper",
        "CFBundleName": "TVTimeHelper",
        "CFBundlePackageType": "BNDL",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
      ],
      to: helperContents.appendingPathComponent("Info.plist")
    )
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: appExecutable)
    try Data((helperSource ?? syntheticHelperSource).utf8).write(to: helperExecutable)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o700],
      ofItemAtPath: appExecutable.path
    )
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o700],
      ofItemAtPath: helperExecutable.path
    )
    return app
  }

  private func writePropertyList(_ value: [String: String], to url: URL) throws {
    let data = try PropertyListSerialization.data(
      fromPropertyList: value,
      format: .xml,
      options: 0
    )
    try data.write(to: url)
  }

  private func pathHasNoSymbolicLinks(_ url: URL) -> Bool {
    var current = URL(fileURLWithPath: "/", isDirectory: true)
    for component in url.standardizedFileURL.pathComponents.dropFirst() {
      current.appendPathComponent(component)
      var metadata = stat()
      let status = current.path.withCString { Darwin.lstat($0, &metadata) }
      if status != 0 || metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFLNK) {
        return false
      }
    }
    return true
  }

  private func directoryIdentity(at url: URL) throws -> DestinationDirectoryIdentity {
    var metadata = stat()
    try url.path.withCString { path in
      guard Darwin.lstat(path, &metadata) == 0 else {
        throw CocoaError(.fileReadUnknown)
      }
    }
    return DestinationDirectoryIdentity(
      device: UInt64(metadata.st_dev),
      inode: UInt64(metadata.st_ino)
    )
  }

  private var syntheticHelperSource: String {
    #"""
    #!/usr/bin/env python3
    import fcntl
    import os
    import signal
    import stat
    import sys
    import time

    def stop_safely(_signal, _frame):
        raise SystemExit(1)

    signal.signal(signal.SIGINT, stop_safely)
    signal.signal(signal.SIGTERM, stop_safely)
    destination = os.fstat(4)
    if not stat.S_ISDIR(destination.st_mode):
        raise SystemExit(2)
    try:
        fcntl.fcntl(3, fcntl.F_GETFD)
    except OSError:
        pass
    else:
        raise SystemExit(4)
    for descriptor in range(5, 256):
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        raise SystemExit(3)
    print('{"protocolVersion":3,"sequence":1,"type":"ready","payload":{"helperVersion":"synthetic","minimumProtocolVersion":3,"maximumProtocolVersion":3,"capabilities":["preflight","cancel","destination-parent-fd","source-receipt-v1"]}}', flush=True)
    print('{"protocolVersion":3,"sequence":2,"type":"cancelled","payload":{"code":"cancelled","message":"Cancelled safely.","retryable":true}}', flush=True)
    time.sleep(12)
    raise SystemExit(1)
    """#
  }

  private var syntheticRecoveryHelperSource: String {
    #"""
    #!/usr/bin/env python3
    import fcntl
    import json
    import os
    import stat
    import struct
    import sys

    def read_exact(stream, count):
        value = stream.read(count)
        if value is None or len(value) != count:
            raise SystemExit(10)
        return value

    control_size = struct.unpack('>I', read_exact(sys.stdin.buffer, 4))[0]
    control = json.loads(read_exact(sys.stdin.buffer, control_size))
    if control.get('type') != 'recover':
        raise SystemExit(11)

    with os.fdopen(3, 'rb', buffering=0, closefd=True) as secret_stream:
        secret_size = struct.unpack('>I', read_exact(secret_stream, 4))[0]
        secret = read_exact(secret_stream, secret_size)
    if secret != b'synthetic-secret':
        raise SystemExit(12)

    destination = os.fstat(4)
    if not stat.S_ISDIR(destination.st_mode):
        raise SystemExit(13)
    os.close(4)
    for descriptor in range(3, 256):
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        raise SystemExit(14)

    print('{"protocolVersion":3,"sequence":1,"type":"ready","payload":{"helperVersion":"synthetic","minimumProtocolVersion":3,"maximumProtocolVersion":3,"capabilities":["recover","cancel","destination-parent-fd","source-receipt-v1"]}}', flush=True)
    print('{"protocolVersion":3,"sequence":2,"type":"failed","payload":{"code":"recovery_failed","message":"Recovery stopped safely.","retryable":true}}', flush=True)
    raise SystemExit(1)
    """#
  }
}
