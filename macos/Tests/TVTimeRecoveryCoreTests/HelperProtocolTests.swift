import Foundation
import Testing

@testable import TVTimeRecoveryCore

@Suite
struct HelperProtocolTests {
  @Test
  func testDecodesReadyAndProgressEvents() throws {
    let ready = HelperReady(
      helperVersion: "1.0.0",
      minimumProtocolVersion: HelperProtocolV3.version,
      maximumProtocolVersion: HelperProtocolV3.version,
      capabilities: ["cancel", "destination-parent-fd"]
    )
    let readyEvent = try TestFixtures.event(type: "ready", payload: ready, sequence: 0)
    expectEqual(readyEvent.protocolVersion, HelperProtocolV3.version)
    expectEqual(readyEvent.sequence, 0)
    expectFalse(readyEvent.isTerminal)
    guard case .ready(let decodedReady) = readyEvent.body else {
      return failTest("Expected a ready event")
    }
    expectEqual(decodedReady, ready)

    let progress = HelperProgress(stage: "analysis", kind: "progress", current: 4, total: 10)
    let progressEvent = try TestFixtures.event(type: "progress", payload: progress)
    expectFalse(progressEvent.isTerminal)
    guard case .progress(let decodedProgress) = progressEvent.body else {
      return failTest("Expected a progress event")
    }
    expectEqual(decodedProgress, progress)
    expectEqual(decodedProgress.recoveryProgress.fractionCompleted, 0.4)
    expectEqual(
      decodedProgress.recoveryProgress.message,
      "Recovering readable titles, favorites, episodes, and watch events…"
    )
  }

  @Test
  func testDecodesStrictPreflightCompletion() throws {
    let expected = TestFixtures.preflight()
    let expectedReceipt = TestFixtures.backupReceipt()
    let event = try TestFixtures.preflightCompletionEvent(
      expected,
      backupReceipt: expectedReceipt
    )
    expectTrue(event.isTerminal)
    guard case .preflightCompleted(let actual) = event.body else {
      return failTest("Expected a preflight completion")
    }
    expectEqual(actual.summary, expected)
    expectEqual(actual.backupReceipt, expectedReceipt)
  }

  @Test
  func testDecodesStrictRecoveryCompletion() throws {
    let expected = TestFixtures.summary()
    let event = try TestFixtures.recoveryCompletionEvent(expected)
    expectTrue(event.isTerminal)
    guard case .recoveryCompleted(let actual) = event.body else {
      return failTest("Expected a recovery completion")
    }
    expectEqual(actual, expected)
  }

  @Test
  func testRejectsIncompleteCompletionPayload() throws {
    struct IncompletePayload: Encodable {
      let preflight = TestFixtures.preflight()
      let extraction = TestFixtures.extraction()
    }

    expectThrowsError(
      try TestFixtures.event(type: "completed", payload: IncompletePayload())
    ) { error in
      expectTrue(error is DecodingError)
    }
  }

  @Test
  func testRejectsImplausiblePreflightAndRecoveryCompletions() throws {
    let incompletePreflight = TestFixtures.preflight(encrypted: false)
    expectThrowsError(try TestFixtures.preflightCompletionEvent(incompletePreflight)) { error in
      expectTrue(error is DecodingError)
    }

    let incompleteRecovery = TestFixtures.summary(
      extraction: TestFixtures.extraction(filesExpected: 7, filesExtracted: 6)
    )
    expectThrowsError(try TestFixtures.recoveryCompletionEvent(incompleteRecovery)) { error in
      expectTrue(error is DecodingError)
    }
  }

  @Test
  func testMissingMalformedAndMismatchedPreflightReceiptsFailClosed() throws {
    let preflight = try jsonObject(TestFixtures.preflight())
    let receipt = try requireValue(
      try jsonObject(TestFixtures.backupReceipt()) as? [String: Any]
    )

    for payload in [
      ["preflight": preflight],
      ["preflight": preflight, "backup_receipt": NSNull()],
    ] {
      expectThrowsError(try decodeCompletedEvent(payload: payload)) { error in
        expectTrue(error is DecodingError)
      }
    }

    var malformedReceipt = receipt
    var manifest = try requireValue(malformedReceipt["manifest_plist"] as? [String: Any])
    manifest["sha256"] = String(repeating: "A", count: 64)
    malformedReceipt["manifest_plist"] = manifest
    expectThrowsError(
      try decodeCompletedEvent(
        payload: ["preflight": preflight, "backup_receipt": malformedReceipt]
      )
    ) { error in
      expectTrue(error is DecodingError)
    }

    var mismatchedReceipt = receipt
    mismatchedReceipt["backup_regular_files"] = 101
    expectThrowsError(
      try decodeCompletedEvent(
        payload: ["preflight": preflight, "backup_receipt": mismatchedReceipt]
      )
    ) { error in
      expectTrue(error is DecodingError)
    }
  }

  @Test
  func testReceiptIsAllowedOnlyOnExactPreflightCompletionPayload() throws {
    let preflight = try jsonObject(TestFixtures.preflight())
    let receipt = try jsonObject(TestFixtures.backupReceipt())
    expectThrowsError(
      try decodeCompletedEvent(
        payload: [
          "preflight": preflight,
          "backup_receipt": receipt,
          "unexpected": true,
        ]
      )
    ) { error in
      expectTrue(error is DecodingError)
    }

    var recovery = try requireValue(
      try jsonObject(TestFixtures.summary()) as? [String: Any]
    )
    recovery["backup_receipt"] = receipt
    expectThrowsError(try decodeCompletedEvent(payload: recovery)) { error in
      expectTrue(error is DecodingError)
    }
  }

  @Test
  func testReceiptRejectsFloatingPointIntegerSpellings() throws {
    let data = try completedEventData(
      payload: [
        "preflight": try jsonObject(TestFixtures.preflight()),
        "backup_receipt": try jsonObject(TestFixtures.backupReceipt()),
      ]
    )
    let source = try requireValue(String(data: data, encoding: .utf8))
    let target = #""root_device":7"#
    let range = try requireValue(source.range(of: target))
    let malformed = Data(
      source.replacingCharacters(in: range, with: #""root_device":7.0"#).utf8
    )
    expectThrowsError(try HelperEventDecoder.decode(malformed)) { error in
      expectTrue(error is DecodingError)
    }
  }

  @Test
  func testReceiptSupportsFullUnsignedRootIdentityRange() throws {
    let receipt = TestFixtures.backupReceipt(
      rootDevice: UInt64.max,
      rootInode: UInt64.max
    )
    let event = try TestFixtures.preflightCompletionEvent(backupReceipt: receipt)
    guard case .preflightCompleted(let completion) = event.body else {
      return failTest("Expected a preflight completion")
    }
    expectEqual(completion.backupReceipt, receipt)
  }

  @Test
  func testDecodesFailureAndCancellationAsTerminalEvents() throws {
    let failure = RecoveryFailure(code: "failed", message: "Stopped safely", retryable: true)
    let failedEvent = try TestFixtures.event(type: "failed", payload: failure)
    let cancelledEvent = try TestFixtures.event(type: "cancelled", payload: failure)

    guard case .failed(let decodedFailure) = failedEvent.body else {
      return failTest("Expected failed event")
    }
    expectEqual(decodedFailure, failure)
    expectTrue(failedEvent.isTerminal)

    guard case .cancelled(let decodedCancellation) = cancelledEvent.body else {
      return failTest("Expected cancelled event")
    }
    expectEqual(decodedCancellation, failure)
    expectTrue(cancelledEvent.isTerminal)
  }

  @Test
  func testRejectsUnsupportedEventTypeAndMalformedPayload() throws {
    expectThrowsError(try TestFixtures.event(type: "surprise", payload: ["value": 1])) {
      error in
      expectTrue(error is DecodingError)
    }

    let malformed = Data(
      #"{"protocolVersion":3,"sequence":1,"type":"progress","payload":{"stage":4}}"#.utf8
    )
    expectThrowsError(try HelperEventDecoder.decode(malformed)) { error in
      expectTrue(error is DecodingError)
    }
  }

  @Test
  func testRequestFrameUsesBigEndianLengthAndExcludesSecret() throws {
    let receipt = TestFixtures.backupReceipt()
    let request = RecoveryRequest(
      action: .recover,
      backupDirectory: URL(fileURLWithPath: "/backup"),
      outputDirectory: URL(fileURLWithPath: "/output"),
      destinationParentIdentity: DestinationDirectoryIdentity(device: 7, inode: 11),
      acknowledgeSensitiveOutput: true,
      backupReceipt: receipt
    )
    let frame = try HelperFrameEncoder.frame(HelperRequestEnvelope(request: request))
    expectGreaterThan(frame.count, 4)

    let length = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    expectEqual(Int(length), frame.count - 4)
    let object = try requireValue(
      JSONSerialization.jsonObject(with: frame.dropFirst(4)) as? [String: Any]
    )
    expectEqual(object["protocolVersion"] as? Int, HelperProtocolV3.version)
    expectEqual(object["type"] as? String, "recover")
    let payload = try requireValue(object["payload"] as? [String: Any])
    expectEqual(
      Set(payload.keys),
      Set([
        "backup_directory", "output_directory", "destination_parent_identity",
        "acknowledge_sensitive_output", "include_raw_cache", "include_decrypted_manifest",
        "backup_receipt",
      ])
    )
    expectEqual(payload["backup_directory"] as? String, "/backup")
    expectEqual(payload["output_directory"] as? String, "/output")
    let identity = try requireValue(payload["destination_parent_identity"] as? [String: Any])
    expectEqual(identity["device"] as? Int, 7)
    expectEqual(identity["inode"] as? Int, 11)
    let encodedReceipt = try requireValue(payload["backup_receipt"] as? [String: Any])
    expectEqual(encodedReceipt["schema_version"] as? Int, 1)
    expectEqual(
      encodedReceipt["contract"] as? String,
      "tvtime-backup-preflight-receipt-v0.2"
    )
    expectNil(payload["password"])
    expectNil(payload["secret"])
  }

  @Test
  func testPreflightRequestExplicitlyEncodesNullBackupReceipt() throws {
    let request = RecoveryRequest(
      action: .preflight,
      backupDirectory: URL(fileURLWithPath: "/backup"),
      outputDirectory: URL(fileURLWithPath: "/output"),
      destinationParentIdentity: DestinationDirectoryIdentity(device: 7, inode: 11),
      acknowledgeSensitiveOutput: false
    )
    let frame = try HelperFrameEncoder.frame(HelperRequestEnvelope(request: request))
    let object = try requireValue(
      JSONSerialization.jsonObject(with: frame.dropFirst(4)) as? [String: Any]
    )
    let payload = try requireValue(object["payload"] as? [String: Any])
    expectTrue(payload["backup_receipt"] is NSNull)
  }

  private func jsonObject<T: Encodable>(_ value: T) throws -> Any {
    try JSONSerialization.jsonObject(with: JSONEncoder().encode(value))
  }

  private func decodeCompletedEvent(payload: [String: Any]) throws -> HelperEvent {
    try HelperEventDecoder.decode(completedEventData(payload: payload))
  }

  private func completedEventData(payload: [String: Any]) throws -> Data {
    let event: [String: Any] = [
      "protocolVersion": HelperProtocolV3.version,
      "sequence": 2,
      "type": "completed",
      "payload": payload,
    ]
    return try JSONSerialization.data(withJSONObject: event, options: [.sortedKeys])
  }
}
