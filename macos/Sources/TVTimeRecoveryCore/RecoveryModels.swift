import Foundation

enum RecoveryOutputContractLimits {
  static let maximumStateBytes: Int64 = 64 * 1024
  static let maximumSummaryBytes: Int64 = 16 * 1024 * 1024
  static let maximumGeneratedArtifactBytes: Int64 = 64 * 1024 * 1024
  static let maximumInventoryBytes: Int64 = 256 * 1024 * 1024
  static let maximumInventoryRows = 100_000
  static let maximumVisualRowsPerTable = 25_000
  static let maximumCombinedVisualRows = 50_000
  static let maximumImageReferenceRows = 25_000
  static let maximumMediaReferenceOccurrences = 100_000
}

public enum RecoveryAction: String, Codable, Sendable {
  case preflight
  case recover
}

public struct DestinationDirectoryIdentity: Codable, Equatable, Sendable {
  public let device: UInt64
  public let inode: UInt64

  public init(device: UInt64, inode: UInt64) {
    self.device = device
    self.inode = inode
  }
}

struct StrictProtocolCodingKey: CodingKey, Hashable {
  let stringValue: String
  let intValue: Int?

  init?(stringValue: String) {
    self.stringValue = stringValue
    intValue = nil
  }

  init?(intValue: Int) {
    stringValue = String(intValue)
    self.intValue = intValue
  }
}

func requireExactProtocolKeys(
  _ decoder: Decoder,
  expected: Set<String>,
  description: String
) throws {
  let container = try decoder.container(keyedBy: StrictProtocolCodingKey.self)
  guard Set(container.allKeys.map(\.stringValue)) == expected else {
    throw DecodingError.dataCorrupted(
      DecodingError.Context(
        codingPath: decoder.codingPath,
        debugDescription: description
      )
    )
  }
}

struct BackupReceipt: Codable, Equatable, Sendable {
  static let expectedSchemaVersion = 1
  static let expectedContract = "tvtime-backup-preflight-receipt-v0.2"

  struct FileSnapshot: Codable, Equatable, Sendable {
    let mode: UInt64
    let size: Int64
    let modifiedNanoseconds: Int64
    let changedNanoseconds: Int64
    let device: UInt64
    let inode: UInt64
    let sha256: String

    enum CodingKeys: String, CodingKey, CaseIterable, Hashable {
      case mode
      case size
      case modifiedNanoseconds = "modified_ns"
      case changedNanoseconds = "changed_ns"
      case device
      case inode
      case sha256
    }

    init(
      mode: UInt64,
      size: Int64,
      modifiedNanoseconds: Int64,
      changedNanoseconds: Int64,
      device: UInt64,
      inode: UInt64,
      sha256: String
    ) {
      self.mode = mode
      self.size = size
      self.modifiedNanoseconds = modifiedNanoseconds
      self.changedNanoseconds = changedNanoseconds
      self.device = device
      self.inode = inode
      self.sha256 = sha256
    }

    init(from decoder: Decoder) throws {
      try requireExactProtocolKeys(
        decoder,
        expected: Set(CodingKeys.allCases.map(\.stringValue)),
        description: "The backup receipt file snapshot had unexpected fields."
      )
      let container = try decoder.container(keyedBy: CodingKeys.self)
      mode = try container.decode(UInt64.self, forKey: .mode)
      size = try container.decode(Int64.self, forKey: .size)
      modifiedNanoseconds = try container.decode(Int64.self, forKey: .modifiedNanoseconds)
      changedNanoseconds = try container.decode(Int64.self, forKey: .changedNanoseconds)
      device = try container.decode(UInt64.self, forKey: .device)
      inode = try container.decode(UInt64.self, forKey: .inode)
      sha256 = try container.decode(String.self, forKey: .sha256)
      guard
        size >= 0,
        modifiedNanoseconds >= 0,
        changedNanoseconds >= 0,
        Self.isLowercaseSHA256(sha256)
      else {
        throw DecodingError.dataCorrupted(
          DecodingError.Context(
            codingPath: decoder.codingPath,
            debugDescription: "The backup receipt file snapshot was malformed."
          )
        )
      }
    }

    private static func isLowercaseSHA256(_ value: String) -> Bool {
      value.utf8.count == 64
        && value.allSatisfy({ $0.isASCII && $0.isHexDigit && !$0.isUppercase })
    }
  }

  let schemaVersion: Int
  let contract: String
  let rootDevice: UInt64
  let rootInode: UInt64
  let backupRegularFiles: Int64
  let backupLogicalBytes: Int64
  let manifestPlist: FileSnapshot
  let manifestDatabase: FileSnapshot
  let statusPlist: FileSnapshot

  enum CodingKeys: String, CodingKey, CaseIterable, Hashable {
    case schemaVersion = "schema_version"
    case contract
    case rootDevice = "root_device"
    case rootInode = "root_inode"
    case backupRegularFiles = "backup_regular_files"
    case backupLogicalBytes = "backup_logical_bytes"
    case manifestPlist = "manifest_plist"
    case manifestDatabase = "manifest_database"
    case statusPlist = "status_plist"
  }

  init(
    schemaVersion: Int = expectedSchemaVersion,
    contract: String = expectedContract,
    rootDevice: UInt64,
    rootInode: UInt64,
    backupRegularFiles: Int64,
    backupLogicalBytes: Int64,
    manifestPlist: FileSnapshot,
    manifestDatabase: FileSnapshot,
    statusPlist: FileSnapshot
  ) {
    self.schemaVersion = schemaVersion
    self.contract = contract
    self.rootDevice = rootDevice
    self.rootInode = rootInode
    self.backupRegularFiles = backupRegularFiles
    self.backupLogicalBytes = backupLogicalBytes
    self.manifestPlist = manifestPlist
    self.manifestDatabase = manifestDatabase
    self.statusPlist = statusPlist
  }

  init(from decoder: Decoder) throws {
    try requireExactProtocolKeys(
      decoder,
      expected: Set(CodingKeys.allCases.map(\.stringValue)),
      description: "The backup receipt had unexpected fields."
    )
    let container = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
    contract = try container.decode(String.self, forKey: .contract)
    rootDevice = try container.decode(UInt64.self, forKey: .rootDevice)
    rootInode = try container.decode(UInt64.self, forKey: .rootInode)
    backupRegularFiles = try container.decode(Int64.self, forKey: .backupRegularFiles)
    backupLogicalBytes = try container.decode(Int64.self, forKey: .backupLogicalBytes)
    manifestPlist = try container.decode(FileSnapshot.self, forKey: .manifestPlist)
    manifestDatabase = try container.decode(FileSnapshot.self, forKey: .manifestDatabase)
    statusPlist = try container.decode(FileSnapshot.self, forKey: .statusPlist)
    guard
      schemaVersion == Self.expectedSchemaVersion,
      contract == Self.expectedContract,
      backupRegularFiles >= 0,
      backupLogicalBytes >= 0
    else {
      throw DecodingError.dataCorrupted(
        DecodingError.Context(
          codingPath: decoder.codingPath,
          debugDescription: "The backup receipt was malformed."
        )
      )
    }
  }

  func matches(_ summary: PreflightSummary) -> Bool {
    Int64(exactly: summary.backupRegularFiles) == backupRegularFiles
      && summary.backupLogicalBytes == backupLogicalBytes
  }
}

public struct RecoveryRequest: Sendable {
  public let action: RecoveryAction
  public let backupDirectory: URL
  public let outputDirectory: URL
  public let destinationParentIdentity: DestinationDirectoryIdentity
  public let acknowledgeSensitiveOutput: Bool
  public let includeRawCache: Bool
  public let includeDecryptedManifest: Bool
  let backupReceipt: BackupReceipt?

  public init(
    action: RecoveryAction,
    backupDirectory: URL,
    outputDirectory: URL,
    destinationParentIdentity: DestinationDirectoryIdentity,
    acknowledgeSensitiveOutput: Bool,
    includeRawCache: Bool = false,
    includeDecryptedManifest: Bool = false
  ) {
    self.init(
      action: action,
      backupDirectory: backupDirectory,
      outputDirectory: outputDirectory,
      destinationParentIdentity: destinationParentIdentity,
      acknowledgeSensitiveOutput: acknowledgeSensitiveOutput,
      includeRawCache: includeRawCache,
      includeDecryptedManifest: includeDecryptedManifest,
      backupReceipt: nil
    )
  }

  init(
    action: RecoveryAction,
    backupDirectory: URL,
    outputDirectory: URL,
    destinationParentIdentity: DestinationDirectoryIdentity,
    acknowledgeSensitiveOutput: Bool,
    includeRawCache: Bool = false,
    includeDecryptedManifest: Bool = false,
    backupReceipt: BackupReceipt?
  ) {
    self.action = action
    self.backupDirectory = backupDirectory
    self.outputDirectory = outputDirectory
    self.destinationParentIdentity = destinationParentIdentity
    self.acknowledgeSensitiveOutput = acknowledgeSensitiveOutput
    self.includeRawCache = includeRawCache
    self.includeDecryptedManifest = includeDecryptedManifest
    self.backupReceipt = backupReceipt
  }
}

public struct RecoveryProgress: Equatable, Sendable {
  public let stage: String
  public let kind: String
  public let message: String
  public let current: Int?
  public let total: Int?

  public init(
    stage: String,
    kind: String,
    message: String,
    current: Int? = nil,
    total: Int? = nil
  ) {
    self.stage = stage
    self.kind = kind
    self.message = message
    self.current = current
    self.total = total
  }

  public var fractionCompleted: Double? {
    guard let current, let total, total > 0 else {
      return nil
    }
    return min(max(Double(current) / Double(total), 0), 1)
  }
}

public struct PreflightSummary: Codable, Equatable, Sendable {
  public let encrypted: Bool
  public let snapshotState: String
  public let backupDate: String
  public let backupRegularFiles: Int
  public let backupLogicalBytes: Int64
  public let manifestDatabaseBytes: Int64
  public let destinationFreeBytes: Int64
  public let minimumWorkingBytes: Int64
  public let hasMinimumSpace: Bool
  public let warnings: [String]

  enum CodingKeys: String, CodingKey {
    case encrypted
    case snapshotState = "snapshot_state"
    case backupDate = "backup_date"
    case backupRegularFiles = "backup_regular_files"
    case backupLogicalBytes = "backup_logical_bytes"
    case manifestDatabaseBytes = "manifest_database_bytes"
    case destinationFreeBytes = "destination_free_bytes"
    case minimumWorkingBytes = "minimum_working_bytes"
    case hasMinimumSpace = "has_minimum_space"
    case warnings
  }

  var hasPlausibleAggregateValues: Bool {
    encrypted
      && snapshotState.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "finished"
      && backupRegularFiles >= 0
      && backupLogicalBytes >= 0
      && manifestDatabaseBytes >= 0
      && destinationFreeBytes >= 0
      && minimumWorkingBytes >= 0
      && hasMinimumSpace
      && hasMinimumSpace == (destinationFreeBytes >= minimumWorkingBytes)
  }
}

public struct ExtractionSummary: Codable, Equatable, Sendable {
  public let filesExpected: Int
  public let filesExtracted: Int
  public let bytesExtracted: Int64
  public let selectedDeclaredBytes: Int64
  public let sizeDiscrepancyCount: Int

  enum CodingKeys: String, CodingKey {
    case filesExpected = "files_expected"
    case filesExtracted = "files_extracted"
    case bytesExtracted = "bytes_extracted"
    case selectedDeclaredBytes = "selected_declared_bytes"
    case sizeDiscrepancyCount = "size_discrepancy_count"
  }

  var hasPlausibleAggregateValues: Bool {
    filesExpected >= 0
      && filesExtracted >= 0
      && filesExtracted == filesExpected
      && filesExpected <= RecoveryOutputContractLimits.maximumInventoryRows
      && bytesExtracted >= 0
      && selectedDeclaredBytes >= 0
      && sizeDiscrepancyCount >= 0
      && sizeDiscrepancyCount <= filesExpected
      && sizeDiscrepancyCount <= RecoveryOutputContractLimits.maximumVisualRowsPerTable
  }
}

public struct AnalysisSummary: Codable, Equatable, Sendable {
  public let seriesLibrary: Int
  public let watchedMovies: Int
  public let movieWatchlist: Int
  public let favoriteShows: Int
  public let favoriteMovies: Int
  public let watchEvents: Int
  public let watchEventsWithTitles: Int
  public let episodeCacheUnique: Int
  public let parserStatus: String

  enum CodingKeys: String, CodingKey {
    case seriesLibrary = "series_library"
    case watchedMovies = "watched_movies"
    case movieWatchlist = "movie_watchlist"
    case favoriteShows = "favorite_shows"
    case favoriteMovies = "favorite_movies"
    case watchEvents = "watch_events"
    case watchEventsWithTitles = "watch_events_with_titles"
    case episodeCacheUnique = "episode_cache_unique"
    case parserStatus = "parser_status"
  }

  public var movieCount: Int {
    let (total, overflow) = watchedMovies.addingReportingOverflow(movieWatchlist)
    guard overflow else {
      return total
    }
    return watchedMovies >= 0 ? Int.max : Int.min
  }

  public var watchEventsWithoutTitles: Int {
    max(0, watchEvents - watchEventsWithTitles)
  }

  public var hasRecoveredRecords: Bool {
    seriesLibrary > 0
      || movieCount > 0
      || favoriteShows > 0
      || favoriteMovies > 0
      || watchEvents > 0
      || episodeCacheUnique > 0
  }

  var hasPlausibleAggregateValues: Bool {
    visualReportRecordCounts.allSatisfy {
      $0 >= 0 && $0 <= RecoveryOutputContractLimits.maximumVisualRowsPerTable
    }
      && visualReportRecordCount <= RecoveryOutputContractLimits.maximumCombinedVisualRows
      && watchEvents >= 0
      && watchEventsWithTitles >= 0
      && watchEventsWithTitles <= watchEvents
      && ["recognized", "empty"].contains(parserStatus)
  }

  var visualReportRecordCount: Int {
    visualReportRecordCounts.reduce(0, +)
  }

  private var visualReportRecordCounts: [Int] {
    [
      seriesLibrary,
      watchedMovies,
      movieWatchlist,
      favoriteShows,
      favoriteMovies,
      watchEvents,
      episodeCacheUnique,
    ]
  }
}

public struct ReportSummary: Codable, Equatable, Sendable {
  public let imageCacheReferences: Int
  public let trailerReferences: Int
  public let mediaURLs: Int
  public let pdfStatus: String
  public let pdfOmissionReason: String?

  enum CodingKeys: String, CodingKey {
    case imageCacheReferences = "image_cache_references"
    case trailerReferences = "trailer_references"
    case mediaURLs = "media_urls"
    case pdfStatus = "pdf_status"
    case pdfOmissionReason = "pdf_omission_reason"
  }

  var hasPlausibleAggregateValues: Bool {
    imageCacheReferences >= 0
      && imageCacheReferences <= RecoveryOutputContractLimits.maximumImageReferenceRows
      && trailerReferences >= 0
      && mediaURLs >= 0
      && trailerReferences <= RecoveryOutputContractLimits.maximumMediaReferenceOccurrences
      && mediaURLs
        <= RecoveryOutputContractLimits.maximumMediaReferenceOccurrences - trailerReferences
      && ["generated", "omitted"].contains(pdfStatus)
      && safePDFOmissionReason != nil
  }

  public var displayPDFOmissionReason: String? {
    guard pdfStatus == "omitted" else {
      return nil
    }
    let fallback =
      "PDF was not created because this Mac could not faithfully render every recovered "
      + "character. The Visual and Markdown reports remain complete."
    guard let reason = pdfOmissionReason?.trimmingCharacters(in: .whitespacesAndNewlines),
      !reason.isEmpty,
      reason.count <= 500,
      !reason.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
      !reason.contains("/"),
      !reason.contains("\\"),
      !reason.localizedCaseInsensitiveContains("file:")
    else {
      return fallback
    }
    return reason
  }

  private var safePDFOmissionReason: String? {
    switch pdfStatus {
    case "generated":
      let reason = pdfOmissionReason?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
      return reason.isEmpty ? "" : nil
    case "omitted":
      return displayPDFOmissionReason
    default:
      return nil
    }
  }
}

public struct RecoveryArtifacts: Codable, Equatable, Sendable {
  public static let expectedExtractionDirectory = "TVTime-Extraction"
  public static let expectedReport =
    "TVTime-Extraction/analysis/TVTime-Recovered-Data.md"
  public static let expectedVisualReport =
    "TVTime-Extraction/analysis/TVTime-Recovered-Data.html"
  public static let expectedPDFReport =
    "TVTime-Extraction/analysis/TVTime-Recovered-Data.pdf"
  public static let expectedAnalysisDirectory = "TVTime-Extraction/analysis"
  public static let expectedRecoveryState =
    "TVTime-Extraction/analysis/recovery_state.json"

  public let extractionDirectory: String
  public let report: String
  public let visualReport: String
  public let pdfReport: String?
  public let analysisDirectory: String
  public let recoveryState: String

  enum CodingKeys: String, CodingKey {
    case extractionDirectory = "extraction_directory"
    case report
    case visualReport = "visual_report"
    case pdfReport = "pdf_report"
    case analysisDirectory = "analysis_directory"
    case recoveryState = "recovery_state"
  }

  var hasExpectedRelativePaths: Bool {
    extractionDirectory == Self.expectedExtractionDirectory
      && report == Self.expectedReport
      && visualReport == Self.expectedVisualReport
      && analysisDirectory == Self.expectedAnalysisDirectory
      && recoveryState == Self.expectedRecoveryState
      && (pdfReport == nil || pdfReport == Self.expectedPDFReport)
  }
}

public struct RecoverySummary: Codable, Equatable, Sendable {
  public let preflight: PreflightSummary
  public let extraction: ExtractionSummary
  public let analysis: AnalysisSummary
  public let report: ReportSummary
  public let artifacts: RecoveryArtifacts

  var hasPlausibleAggregateValues: Bool {
    preflight.hasPlausibleAggregateValues
      && extraction.hasPlausibleAggregateValues
      && analysis.hasPlausibleAggregateValues
      && report.hasPlausibleAggregateValues
      && artifacts.hasExpectedRelativePaths
      && ((report.pdfStatus == "generated") == (artifacts.pdfReport != nil))
      && analysis.visualReportRecordCount
        <= (RecoveryOutputContractLimits.maximumCombinedVisualRows
          - extraction.sizeDiscrepancyCount)
  }
}

public enum RecoveryCancellationOrigin: Int, Equatable, Sendable {
  case cancelButton
  case windowClose
  case applicationQuit
}

public struct RecoveryCancellationPrompt: Identifiable, Equatable, Sendable {
  public let id: UUID
  public let origin: RecoveryCancellationOrigin

  init(id: UUID = UUID(), origin: RecoveryCancellationOrigin) {
    self.id = id
    self.origin = origin
  }
}

public struct RecoveryFailure: Codable, Equatable, Sendable {
  public let code: String
  public let message: String
  public let retryable: Bool
}

public enum RecoveryPhase: Equatable, Sendable {
  case chooseBackup
  case chooseDestination
  case preflighting(RecoveryProgress)
  case confirm(PreflightSummary)
  case running(RecoveryProgress)
  case validating(RecoveryProgress)
  case cancelling
  case completed(RecoverySummary)
  case failed(RecoveryFailure)

  public var isBusy: Bool {
    switch self {
    case .preflighting, .running, .validating, .cancelling:
      true
    default:
      false
    }
  }
}
