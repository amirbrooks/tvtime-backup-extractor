import CoreFoundation
import Foundation

public enum HelperProtocolV3 {
  public static let version = 3
  public static let secretFileDescriptor: Int32 = 3
  public static let destinationParentFileDescriptor: Int32 = 4
  public static let maximumFrameBytes = 1_048_576
  public static let maximumSecretBytes = 16_384
}

struct HelperRequestEnvelope: Encodable, Sendable {
  let protocolVersion = HelperProtocolV3.version
  let type: RecoveryAction
  let payload: Payload

  init(request: RecoveryRequest) {
    type = request.action
    payload = Payload(request: request)
  }

  struct Payload: Encodable, Sendable {
    let backupDirectory: String
    let outputDirectory: String
    let destinationParentIdentity: DestinationDirectoryIdentity
    let acknowledgeSensitiveOutput: Bool
    let includeRawCache: Bool
    let includeDecryptedManifest: Bool
    let backupReceipt: BackupReceipt?

    init(request: RecoveryRequest) {
      backupDirectory = request.backupDirectory.path
      outputDirectory = request.outputDirectory.path
      destinationParentIdentity = request.destinationParentIdentity
      acknowledgeSensitiveOutput = request.acknowledgeSensitiveOutput
      includeRawCache = request.includeRawCache
      includeDecryptedManifest = request.includeDecryptedManifest
      backupReceipt = request.backupReceipt
    }

    enum CodingKeys: String, CodingKey {
      case backupDirectory = "backup_directory"
      case outputDirectory = "output_directory"
      case destinationParentIdentity = "destination_parent_identity"
      case acknowledgeSensitiveOutput = "acknowledge_sensitive_output"
      case includeRawCache = "include_raw_cache"
      case includeDecryptedManifest = "include_decrypted_manifest"
      case backupReceipt = "backup_receipt"
    }

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(backupDirectory, forKey: .backupDirectory)
      try container.encode(outputDirectory, forKey: .outputDirectory)
      try container.encode(destinationParentIdentity, forKey: .destinationParentIdentity)
      try container.encode(acknowledgeSensitiveOutput, forKey: .acknowledgeSensitiveOutput)
      try container.encode(includeRawCache, forKey: .includeRawCache)
      try container.encode(includeDecryptedManifest, forKey: .includeDecryptedManifest)
      if let backupReceipt {
        try container.encode(backupReceipt, forKey: .backupReceipt)
      } else {
        try container.encodeNil(forKey: .backupReceipt)
      }
    }
  }
}

struct HelperCancelEnvelope: Encodable, Sendable {
  let protocolVersion = HelperProtocolV3.version
  let type = "cancel"
}

public struct HelperReady: Codable, Equatable, Sendable {
  public let helperVersion: String
  public let minimumProtocolVersion: Int
  public let maximumProtocolVersion: Int
  public let capabilities: [String]
}

public struct HelperProgress: Codable, Equatable, Sendable {
  public let stage: String
  public let kind: String
  public let current: Int?
  public let total: Int?

  public var recoveryProgress: RecoveryProgress {
    RecoveryProgress(
      stage: stage,
      kind: kind,
      message: Self.humanReadableMessage(stage: stage, kind: kind),
      current: current,
      total: total
    )
  }

  private static func humanReadableMessage(stage: String, kind: String) -> String {
    switch (stage, kind) {
    case ("preflight", "started"):
      "Validating the encrypted backup and private output storage…"
    case ("preflight", "progress"):
      "Inspecting the backup without modifying it…"
    case ("preflight", "completed"):
      "The backup and private output storage passed preflight checks."
    case ("extraction", "started"):
      "Opening the encrypted backup and selecting TV Time data…"
    case ("extraction", "progress"):
      "Copying selected TV Time files…"
    case ("extraction", "completed"):
      "The selected TV Time files were copied and inventoried."
    case ("analysis", "started"), ("analysis", "progress"):
      "Recovering readable titles, favorites, episodes, and watch events…"
    case ("analysis", "completed"):
      "Readable TV Time tables were created."
    case ("report", "started"), ("report", "progress"):
      "Building the human-readable private recovery report…"
    case ("report", "completed"):
      "The private report and media-reference tables are ready."
    case ("complete", "completed"):
      "Recovery completed successfully."
    default:
      "Recovery is continuing safely…"
    }
  }
}

public struct PreflightCompletion: Equatable, Sendable {
  public let summary: PreflightSummary
  let backupReceipt: BackupReceipt
}

private struct HelperCompletionPayload: Decodable, Sendable {
  enum Body: Sendable {
    case preflight(PreflightCompletion)
    case recovery(RecoverySummary)
  }

  let body: Body

  enum CodingKeys: String, CodingKey, CaseIterable, Hashable {
    case preflight
    case backupReceipt = "backup_receipt"
    case extraction
    case analysis
    case report
    case artifacts
  }

  init(from decoder: Decoder) throws {
    let preflightKeys: Set<String> = ["preflight", "backup_receipt"]
    let recoveryKeys: Set<String> = [
      "preflight", "extraction", "analysis", "report", "artifacts",
    ]
    let dynamicContainer = try decoder.container(keyedBy: StrictProtocolCodingKey.self)
    let actualKeys = Set(dynamicContainer.allKeys.map(\.stringValue))
    guard actualKeys == preflightKeys || actualKeys == recoveryKeys else {
      throw DecodingError.dataCorrupted(
        DecodingError.Context(
          codingPath: decoder.codingPath,
          debugDescription: "The helper returned an incomplete completion payload."
        )
      )
    }
    let container = try decoder.container(keyedBy: CodingKeys.self)

    if actualKeys == preflightKeys {
      let summary = try container.decode(PreflightSummary.self, forKey: .preflight)
      let backupReceipt = try container.decode(BackupReceipt.self, forKey: .backupReceipt)
      guard summary.hasPlausibleAggregateValues, backupReceipt.matches(summary) else {
        throw DecodingError.dataCorrupted(
          DecodingError.Context(
            codingPath: decoder.codingPath,
            debugDescription: "The helper returned an invalid preflight receipt."
          )
        )
      }
      body = .preflight(
        PreflightCompletion(summary: summary, backupReceipt: backupReceipt)
      )
      return
    }

    if actualKeys == recoveryKeys {
      let summary = RecoverySummary(
        preflight: try container.decode(PreflightSummary.self, forKey: .preflight),
        extraction: try container.decode(ExtractionSummary.self, forKey: .extraction),
        analysis: try container.decode(AnalysisSummary.self, forKey: .analysis),
        report: try container.decode(ReportSummary.self, forKey: .report),
        artifacts: try container.decode(RecoveryArtifacts.self, forKey: .artifacts)
      )
      guard summary.hasPlausibleAggregateValues else {
        throw DecodingError.dataCorrupted(
          DecodingError.Context(
            codingPath: decoder.codingPath,
            debugDescription: "The helper returned invalid aggregate values."
          )
        )
      }
      body = .recovery(summary)
      return
    }

    throw DecodingError.dataCorrupted(
      DecodingError.Context(
        codingPath: decoder.codingPath,
        debugDescription: "The helper returned an incomplete completion payload."
      )
    )
  }
}

public struct HelperEvent: Decodable, Sendable {
  public enum Body: Sendable {
    case ready(HelperReady)
    case progress(HelperProgress)
    case preflightCompleted(PreflightCompletion)
    case recoveryCompleted(RecoverySummary)
    case failed(RecoveryFailure)
    case cancelled(RecoveryFailure)
  }

  public let protocolVersion: Int
  public let sequence: Int
  public let body: Body

  public var isTerminal: Bool {
    switch body {
    case .preflightCompleted, .recoveryCompleted, .failed, .cancelled:
      true
    case .ready, .progress:
      false
    }
  }

  enum CodingKeys: String, CodingKey {
    case protocolVersion
    case sequence
    case type
    case payload
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    protocolVersion = try container.decode(Int.self, forKey: .protocolVersion)
    sequence = try container.decode(Int.self, forKey: .sequence)
    let type = try container.decode(String.self, forKey: .type)

    switch type {
    case "ready":
      body = .ready(try container.decode(HelperReady.self, forKey: .payload))
    case "progress":
      body = .progress(try container.decode(HelperProgress.self, forKey: .payload))
    case "completed":
      let completion = try container.decode(HelperCompletionPayload.self, forKey: .payload)
      switch completion.body {
      case .preflight(let completion):
        body = .preflightCompleted(completion)
      case .recovery(let summary):
        body = .recoveryCompleted(summary)
      }
    case "failed":
      body = .failed(try container.decode(RecoveryFailure.self, forKey: .payload))
    case "cancelled":
      body = .cancelled(try container.decode(RecoveryFailure.self, forKey: .payload))
    default:
      throw DecodingError.dataCorruptedError(
        forKey: .type,
        in: container,
        debugDescription: "The helper returned an unsupported event type."
      )
    }
  }
}

enum HelperEventDecoder {
  static func decode(_ data: Data) throws -> HelperEvent {
    do {
      try StrictJSONValidator.validate(
        data,
        maximumBytes: Int64(HelperProtocolV3.maximumFrameBytes)
      )
      try validateBackupReceiptIntegerTypes(data)
    } catch {
      throw DecodingError.dataCorrupted(
        DecodingError.Context(
          codingPath: [],
          debugDescription: "The helper returned malformed strict JSON."
        )
      )
    }
    return try JSONDecoder().decode(HelperEvent.self, from: data)
  }

  private static func validateBackupReceiptIntegerTypes(_ data: Data) throws {
    guard
      let event = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      event["type"] as? String == "completed",
      let payload = event["payload"] as? [String: Any],
      let receiptValue = payload["backup_receipt"],
      !(receiptValue is NSNull)
    else {
      return
    }
    guard let receipt = receiptValue as? [String: Any] else {
      throw StrictJSONValidationError.invalidJSON
    }
    for key in [
      "schema_version", "backup_regular_files", "backup_logical_bytes",
    ] {
      guard isExactNonnegativeInteger(receipt[key], unsigned: false) else {
        throw StrictJSONValidationError.invalidJSON
      }
    }
    for key in ["root_device", "root_inode"] {
      guard isExactNonnegativeInteger(receipt[key], unsigned: true) else {
        throw StrictJSONValidationError.invalidJSON
      }
    }
    for key in ["manifest_plist", "manifest_database", "status_plist"] {
      guard let file = receipt[key] as? [String: Any] else {
        throw StrictJSONValidationError.invalidJSON
      }
      for field in ["size", "modified_ns", "changed_ns"] {
        guard isExactNonnegativeInteger(file[field], unsigned: false) else {
          throw StrictJSONValidationError.invalidJSON
        }
      }
      for field in ["mode", "device", "inode"] {
        guard isExactNonnegativeInteger(file[field], unsigned: true) else {
          throw StrictJSONValidationError.invalidJSON
        }
      }
    }
  }

  private static func isExactNonnegativeInteger(_ value: Any?, unsigned: Bool) -> Bool {
    guard
      let number = value as? NSNumber,
      CFGetTypeID(number) == CFNumberGetTypeID(),
      !CFNumberIsFloatType(number)
    else {
      return false
    }
    if unsigned {
      return UInt64(number.stringValue) != nil
    }
    guard let integer = Int64(number.stringValue) else {
      return false
    }
    return integer >= 0
  }
}

enum HelperFrameEncoder {
  static func frame<T: Encodable>(_ value: T) throws -> Data {
    try frame(JSONEncoder().encode(value), maximumBytes: HelperProtocolV3.maximumFrameBytes)
  }

  private static func frame(_ payload: Data, maximumBytes: Int) throws -> Data {
    guard !payload.isEmpty, payload.count <= maximumBytes, payload.count <= Int(UInt32.max) else {
      throw HelperClientError.invalidFrame
    }
    var length = UInt32(payload.count).bigEndian
    var framed = Data()
    Swift.withUnsafeBytes(of: &length) { framed.append(contentsOf: $0) }
    framed.append(payload)
    return framed
  }
}

public enum HelperClientError: LocalizedError, Sendable {
  case helperUnavailable
  case helperBusy
  case invalidFrame
  case launchFailed
  case communicationFailed
  case invalidEventStream
  case incompatibleProtocol
  case helperExitedUnexpectedly
  case destinationChanged

  public var errorDescription: String? {
    switch self {
    case .helperUnavailable:
      "The bundled recovery helper is unavailable. Reinstall this application."
    case .helperBusy:
      "A recovery operation is already running."
    case .invalidFrame, .communicationFailed, .invalidEventStream:
      "The app and its bundled recovery helper could not communicate safely."
    case .launchFailed:
      "The bundled recovery helper could not be started."
    case .incompatibleProtocol:
      "This app and its bundled recovery helper are incompatible. Reinstall the application."
    case .helperExitedUnexpectedly:
      "Recovery stopped unexpectedly. The source backup was not intentionally changed."
    case .destinationChanged:
      "The private output storage changed before the helper started. Start over before recovering data."
    }
  }
}
