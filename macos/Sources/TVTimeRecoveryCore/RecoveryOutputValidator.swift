import CryptoKit
import Darwin
import Foundation

enum RecoveryOutputValidator {
  private static let recoveryStateSchemaVersion = 2
  private static let recoveryStateContract = "tvtime-recovery-state-v0.2"
  private static let extractionRunStateContract = "tvtime-extraction-run-state-v0.2"
  private static let analysisSummaryContract = "tvtime-analysis-summary-v0.2"
  private static let maximumStateBytes = RecoveryOutputContractLimits.maximumStateBytes
  private static let maximumAnalysisSummaryBytes = RecoveryOutputContractLimits.maximumSummaryBytes
  private static let maximumArtifactBytes =
    RecoveryOutputContractLimits.maximumGeneratedArtifactBytes
  private static let maximumInventoryBytes = RecoveryOutputContractLimits.maximumInventoryBytes
  private static let maximumDomainsBytes: Int64 = 32 * 1024
  private static let maximumAnalysisCSVRows = 100_000
  private static let maximumCSVSpreadsheetEscapes = 100_000
  private static let maximumCSVMetadataStringBytes = 1_024
  private static let sourceSnapshotContract = "tvtime-source-snapshot-v0.2"
  private static let rawTreeDigestPrefix = Data("tvtime-raw-tree-digest-v0.2\0".utf8)
  private static let trustedDarwinRootAliases = [
    (alias: "/etc", target: "/private/etc"),
    (alias: "/tmp", target: "/private/tmp"),
    (alias: "/var", target: "/private/var"),
  ]

  static func validate(
    _ summary: RecoverySummary,
    beneath outputDirectory: URL,
    beforeFinalCompletionMarkerRead: (() throws -> Void)? = nil
  ) throws {
    try Task.checkCancellation()
    guard summary.hasPlausibleAggregateValues else {
      throw RecoveryOutputValidationError.invalidSummary
    }

    let root = try openValidationRoot(outputDirectory)
    defer { Darwin.close(root.descriptor) }
    try requireExactSubdirectoryMembership(
      root.descriptor,
      expectedNames: [RecoveryArtifacts.expectedExtractionDirectory]
    )

    let artifacts = summary.artifacts
    let extractionRootURL = try artifactURL(
      relativePath: artifacts.extractionDirectory,
      beneath: root.url
    )
    let extractionRootDescriptor = try openArtifactNoFollow(
      at: extractionRootURL,
      beneath: root,
      expectedType: .directory
    )
    defer { Darwin.close(extractionRootDescriptor) }
    let extractionRoot = DirectoryAnchor(
      url: extractionRootURL,
      descriptor: extractionRootDescriptor
    )
    try requireExactSubdirectoryMembership(
      extractionRootDescriptor,
      expectedNames: ["analysis", "manifest", "metadata", "raw"]
    )
    try validateRelativeArtifact(
      artifacts.analysisDirectory,
      beneath: root,
      expectedType: .directory
    )
    let manifestDirectory = try artifactURL(
      relativePath: "\(RecoveryArtifacts.expectedExtractionDirectory)/manifest",
      beneath: root.url
    )
    let manifestDescriptor = try openArtifactNoFollow(
      at: manifestDirectory,
      beneath: root,
      expectedType: .directory
    )
    defer { Darwin.close(manifestDescriptor) }
    try requireEmptyDirectory(manifestDescriptor)

    let recoveryStateURL = try artifactURL(
      relativePath: artifacts.recoveryState,
      beneath: root.url
    )
    let recoveryStateSnapshot: RegularFileSnapshot
    do {
      recoveryStateSnapshot = try readRegularFile(
        at: recoveryStateURL,
        beneath: root,
        maximumBytes: maximumStateBytes,
        captureAll: true
      )
    } catch RecoveryOutputValidationError.artifactIntegrityFailure {
      throw RecoveryOutputValidationError.unreadableCompletionMarker
    }
    guard let recoveryStateData = recoveryStateSnapshot.data else {
      throw RecoveryOutputValidationError.unreadableCompletionMarker
    }
    let state: RecoveryCompletionState
    do {
      try validateExactRecoveryCompletionSchema(recoveryStateData)
      state = try JSONDecoder().decode(RecoveryCompletionState.self, from: recoveryStateData)
    } catch is CancellationError {
      throw CancellationError()
    } catch {
      throw RecoveryOutputValidationError.incompleteOutput
    }

    guard
      state.schemaVersion == recoveryStateSchemaVersion,
      state.contract == recoveryStateContract,
      state.status == "complete",
      isPlausibleTimestamp(state.completedUTC),
      state.aggregates.extraction == summary.extraction,
      state.aggregates.analysis == summary.analysis,
      state.aggregates.report == summary.report,
      state.pdf.status == summary.report.pdfStatus,
      state.pdf.artifactID == (summary.report.pdfStatus == "generated" ? "pdf_report" : nil),
      state.sourceSnapshot.isPlausible,
      state.sourceSnapshot.rawTree.files == summary.extraction.filesExtracted,
      state.sourceSnapshot.rawTree.byteSize == summary.extraction.bytesExtracted
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }

    let expectedArtifacts = expectedArtifacts(pdfStatus: summary.report.pdfStatus)
    guard
      state.artifacts.count == expectedArtifacts.count,
      state.artifacts.map(\.id) == expectedArtifacts.map(\.id),
      Set(state.artifacts.map(\.id)).count == state.artifacts.count
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }

    var snapshotsByID: [String: RegularFileSnapshot] = [:]
    for (binding, expected) in zip(state.artifacts, expectedArtifacts) {
      try Task.checkCancellation()
      guard
        binding.id == expected.id,
        binding.relativePath == expected.relativePath,
        binding.byteSize > 0,
        binding.byteSize <= expected.maximumBytes,
        binding.sha256.count == 64,
        binding.sha256.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
      else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      let artifact = try artifactURL(
        relativePath: binding.relativePath,
        beneath: extractionRoot.url
      )
      let snapshot = try readRegularFile(
        at: artifact,
        beneath: extractionRoot,
        maximumBytes: expected.maximumBytes,
        captureAll: expected.captureAll
      )
      guard snapshot.byteSize == binding.byteSize, snapshot.sha256 == binding.sha256 else {
        throw RecoveryOutputValidationError.artifactIntegrityFailure
      }
      try validateFormat(snapshot.data ?? snapshot.prefix, expected: expected.format)
      snapshotsByID[binding.id] = snapshot
    }

    guard
      let runStateData = snapshotsByID["extraction_run_state"]?.data,
      let inventorySnapshot = snapshotsByID["extraction_inventory"],
      let inventoryData = inventorySnapshot.data,
      let extractionSummaryData = snapshotsByID["extraction_summary"]?.data,
      let domainsData = snapshotsByID["extraction_domains"]?.data,
      let analysisSummaryData = snapshotsByID["analysis_summary"]?.data
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    guard
      inventorySnapshot.byteSize == state.sourceSnapshot.inventory.byteSize,
      inventorySnapshot.sha256 == state.sourceSnapshot.inventory.sha256
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    let inventoryEntries = try parseInventory(inventoryData)
    let inventoryDeclaredByteTotal = try declaredByteTotal(inventoryEntries)
    let runState = try validateExtractionRunState(
      runStateData,
      expected: summary.extraction
    )
    guard runState.sourceSnapshot == state.sourceSnapshot else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    try validateExtractionSummary(
      extractionSummaryData,
      domainsData: domainsData,
      expected: summary.extraction,
      expectedCompletedUTC: runState.completedUTC,
      expectedSelectedDeclaredBytes: inventoryDeclaredByteTotal,
      expectedSizeDiscrepancies: inventoryEntries.compactMap(\.sizeDiscrepancy)
    )
    try validateRawTree(
      entries: inventoryEntries,
      expected: state.sourceSnapshot,
      beneath: extractionRoot
    )
    try validateAnalysisSummary(analysisSummaryData, expected: summary.analysis)
    try requireAbsent(
      relativePath: "analysis/cache_responses",
      beneath: extractionRoot
    )
    let metadataDirectory = try artifactURL(
      relativePath: "metadata",
      beneath: extractionRoot.url
    )
    let analysisDirectory = try artifactURL(
      relativePath: "analysis",
      beneath: extractionRoot.url
    )
    let metadataMembership = try expectedDirectoryMembership(
      directory: "metadata",
      artifacts: expectedArtifacts,
      additionalNames: []
    )
    let analysisMembership = try expectedDirectoryMembership(
      directory: "analysis",
      artifacts: expectedArtifacts,
      // recovery_state.json binds every other sealed artifact and cannot bind
      // its own bytes. Exact membership makes that self-marker exception explicit.
      additionalNames: ["recovery_state.json"]
    )
    try requireExactRegularFileMembership(
      at: metadataDirectory,
      beneath: extractionRoot,
      expectedNames: metadataMembership
    )
    try requireExactRegularFileMembership(
      at: analysisDirectory,
      beneath: extractionRoot,
      expectedNames: analysisMembership
    )

    try beforeFinalCompletionMarkerRead?()
    let finalRecoveryStateSnapshot = try readRegularFile(
      at: recoveryStateURL,
      beneath: root,
      maximumBytes: maximumStateBytes,
      captureAll: true
    )
    guard
      finalRecoveryStateSnapshot.byteSize == recoveryStateSnapshot.byteSize,
      finalRecoveryStateSnapshot.sha256 == recoveryStateSnapshot.sha256,
      finalRecoveryStateSnapshot.data == recoveryStateData
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
  }

  private static func validateExactRecoveryCompletionSchema(_ data: Data) throws {
    let root = try exactJSONObject(
      strictJSONObject(data, maximumBytes: maximumStateBytes),
      keys: [
        "schema_version", "contract", "status", "completed_utc", "pdf", "source_snapshot",
        "aggregates", "artifacts",
      ]
    )
    let pdf = try exactJSONObject(
      root["pdf"],
      keys: ["status", "artifact_id"]
    )
    try validateExactSourceSnapshotSchema(root["source_snapshot"])
    let aggregates = try exactJSONObject(
      root["aggregates"],
      keys: ["extraction", "analysis", "report"]
    )
    _ = try exactJSONObject(
      aggregates["extraction"],
      keys: [
        "files_expected", "files_extracted", "bytes_extracted", "selected_declared_bytes",
        "size_discrepancy_count",
      ]
    )
    _ = try exactJSONObject(
      aggregates["analysis"],
      keys: [
        "series_library", "watched_movies", "movie_watchlist", "favorite_shows",
        "favorite_movies", "watch_events", "watch_events_with_titles", "episode_cache_unique",
        "parser_status",
      ]
    )
    guard let pdfStatus = pdf["status"] as? String else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    var reportKeys: Set<String> = [
      "image_cache_references", "trailer_references", "media_urls", "pdf_status",
    ]
    if pdfStatus == "omitted" {
      reportKeys.insert("pdf_omission_reason")
    }
    _ = try exactJSONObject(aggregates["report"], keys: reportKeys)

    guard let artifacts = root["artifacts"] as? [Any] else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    for artifact in artifacts {
      try Task.checkCancellation()
      _ = try exactJSONObject(
        artifact,
        keys: ["id", "relative_path", "bytes", "sha256"]
      )
    }
  }

  private static func validateExactExtractionRunStateSchema(_ data: Data) throws {
    let root = try exactJSONObject(
      strictJSONObject(data, maximumBytes: maximumStateBytes),
      keys: [
        "schema_version", "contract", "status", "completed_utc", "files_expected",
        "files_extracted", "bytes_extracted", "selected_declared_bytes",
        "size_discrepancy_count", "source_snapshot",
      ]
    )
    try validateExactSourceSnapshotSchema(root["source_snapshot"])
  }

  private static func validateExactExtractionSummarySchema(_ data: Data) throws {
    let root = try exactJSONObject(
      strictJSONObject(data, maximumBytes: maximumAnalysisSummaryBytes),
      keys: [
        "bundle_id", "domains", "files_expected", "files_extracted", "failures",
        "bytes_extracted", "selected_declared_bytes", "size_discrepancies",
        "decrypted_manifest_included", "completed_utc",
      ]
    )
    guard let discrepancies = root["size_discrepancies"] as? [Any] else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    for discrepancy in discrepancies {
      try Task.checkCancellation()
      _ = try exactJSONObject(
        discrepancy,
        keys: ["domain", "relative_path", "declared_size", "actual_size"]
      )
    }
  }

  private static func validateExactAnalysisSummarySchema(_ data: Data) throws {
    let root = try exactJSONObject(
      strictJSONObject(data, maximumBytes: maximumAnalysisSummaryBytes),
      keys: [
        "dio_cache_quick_check", "parser_status", "recognized_payloads", "cache_rows",
        "unique_cache_payloads", "raw_cache_exported",
        "profile_payloads_detected_not_exported", "watch_events", "movie_library",
        "watched_movies", "movie_watchlist", "watch_events_with_titles", "series_library",
        "favorite_movies", "favorite_shows", "episode_cache_rows", "episode_cache_unique",
        "sqlite_databases", "sqlite_integrity", "plist_files",
        "csv_spreadsheet_escaped_cells", "schema_version", "contract", "status",
      ]
    )
    guard root["sqlite_integrity"] is [String: Any],
      let escapeMetadata = root["csv_spreadsheet_escaped_cells"] as? [String: Any]
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    for value in escapeMetadata.values {
      try Task.checkCancellation()
      guard let coordinates = value as? [Any] else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      for coordinate in coordinates {
        _ = try exactJSONObject(coordinate, keys: ["row", "field"])
      }
    }
  }

  private static func validateExactSourceSnapshotSchema(_ value: Any?) throws {
    let sourceSnapshot = try exactJSONObject(
      value,
      keys: ["contract", "inventory", "raw_tree"]
    )
    _ = try exactJSONObject(
      sourceSnapshot["inventory"],
      keys: ["bytes", "sha256"]
    )
    _ = try exactJSONObject(
      sourceSnapshot["raw_tree"],
      keys: ["files", "bytes", "sha256"]
    )
  }

  private static func strictJSONObject(
    _ data: Data,
    maximumBytes: Int64
  ) throws -> [String: Any] {
    try StrictJSONValidator.validate(data, maximumBytes: maximumBytes)
    let decoded = try JSONSerialization.jsonObject(with: data)
    guard let object = decoded as? [String: Any] else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    return object
  }

  private static func exactJSONObject(
    _ value: Any?,
    keys: Set<String>
  ) throws -> [String: Any] {
    guard
      let object = value as? [String: Any],
      Set(object.keys) == keys
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    return object
  }

  private struct RecoveryCompletionState: Decodable {
    let schemaVersion: Int
    let contract: String
    let status: String
    let completedUTC: String
    let pdf: PDFState
    let sourceSnapshot: SourceSnapshot
    let aggregates: AggregateState
    let artifacts: [ArtifactBinding]

    enum CodingKeys: String, CodingKey {
      case schemaVersion = "schema_version"
      case contract
      case status
      case completedUTC = "completed_utc"
      case pdf
      case sourceSnapshot = "source_snapshot"
      case aggregates
      case artifacts
    }
  }

  private struct SourceSnapshot: Decodable, Equatable {
    let contract: String
    let inventory: FileIdentity
    let rawTree: RawTreeIdentity

    enum CodingKeys: String, CodingKey {
      case contract
      case inventory
      case rawTree = "raw_tree"
    }

    var isPlausible: Bool {
      contract == RecoveryOutputValidator.sourceSnapshotContract
        && inventory.byteSize > 0
        && inventory.hasPlausibleHash
        && rawTree.files >= 0
        && rawTree.byteSize >= 0
        && rawTree.hasPlausibleHash
    }
  }

  private struct FileIdentity: Decodable, Equatable {
    let byteSize: Int64
    let sha256: String

    enum CodingKeys: String, CodingKey {
      case byteSize = "bytes"
      case sha256
    }

    var hasPlausibleHash: Bool { RecoveryOutputValidator.isLowercaseSHA256(sha256) }
  }

  private struct RawTreeIdentity: Decodable, Equatable {
    let files: Int
    let byteSize: Int64
    let sha256: String

    enum CodingKeys: String, CodingKey {
      case files
      case byteSize = "bytes"
      case sha256
    }

    var hasPlausibleHash: Bool { RecoveryOutputValidator.isLowercaseSHA256(sha256) }
  }

  private struct PDFState: Decodable {
    let status: String
    let artifactID: String?

    enum CodingKeys: String, CodingKey {
      case status
      case artifactID = "artifact_id"
    }
  }

  private struct AggregateState: Decodable {
    let extraction: ExtractionSummary
    let analysis: AnalysisSummary
    let report: ReportSummary
  }

  private struct ArtifactBinding: Decodable {
    let id: String
    let relativePath: String
    let byteSize: Int64
    let sha256: String

    enum CodingKeys: String, CodingKey {
      case id
      case relativePath = "relative_path"
      case byteSize = "bytes"
      case sha256
    }
  }

  private struct ExtractionRunState: Decodable {
    let schemaVersion: Int
    let contract: String
    let status: String
    let completedUTC: String
    let filesExpected: Int
    let filesExtracted: Int
    let bytesExtracted: Int64
    let selectedDeclaredBytes: Int64
    let sizeDiscrepancyCount: Int
    let sourceSnapshot: SourceSnapshot

    enum CodingKeys: String, CodingKey {
      case schemaVersion = "schema_version"
      case contract
      case status
      case completedUTC = "completed_utc"
      case filesExpected = "files_expected"
      case filesExtracted = "files_extracted"
      case bytesExtracted = "bytes_extracted"
      case selectedDeclaredBytes = "selected_declared_bytes"
      case sizeDiscrepancyCount = "size_discrepancy_count"
      case sourceSnapshot = "source_snapshot"
    }

    var summary: ExtractionSummary {
      ExtractionSummary(
        filesExpected: filesExpected,
        filesExtracted: filesExtracted,
        bytesExtracted: bytesExtracted,
        selectedDeclaredBytes: selectedDeclaredBytes,
        sizeDiscrepancyCount: sizeDiscrepancyCount
      )
    }
  }

  private struct ValidatedExtractionRunState {
    let sourceSnapshot: SourceSnapshot
    let completedUTC: String
  }

  private struct ExtractionMetadataSummary: Decodable {
    let bundleID: String
    let domains: [String]
    let filesExpected: Int
    let filesExtracted: Int
    let failures: [EmptyFailure]
    let bytesExtracted: Int64
    let selectedDeclaredBytes: Int64
    let sizeDiscrepancies: [ExtractionSizeDiscrepancy]
    let decryptedManifestIncluded: Bool
    let completedUTC: String

    enum CodingKeys: String, CodingKey {
      case bundleID = "bundle_id"
      case domains
      case filesExpected = "files_expected"
      case filesExtracted = "files_extracted"
      case failures
      case bytesExtracted = "bytes_extracted"
      case selectedDeclaredBytes = "selected_declared_bytes"
      case sizeDiscrepancies = "size_discrepancies"
      case decryptedManifestIncluded = "decrypted_manifest_included"
      case completedUTC = "completed_utc"
    }

    var summary: ExtractionSummary {
      ExtractionSummary(
        filesExpected: filesExpected,
        filesExtracted: filesExtracted,
        bytesExtracted: bytesExtracted,
        selectedDeclaredBytes: selectedDeclaredBytes,
        sizeDiscrepancyCount: sizeDiscrepancies.count
      )
    }
  }

  private struct EmptyFailure: Decodable {}

  private struct ExtractionSizeDiscrepancy: Decodable, Equatable {
    let domain: String
    let relativePath: String
    let declaredSize: Int64
    let actualSize: Int64

    enum CodingKeys: String, CodingKey {
      case domain
      case relativePath = "relative_path"
      case declaredSize = "declared_size"
      case actualSize = "actual_size"
    }

    var isPlausible: Bool {
      RecoveryOutputValidator.isSafeInventoryDomain(domain)
        && RecoveryOutputValidator.isSafeInventoryRelativePath(relativePath)
        && declaredSize >= 0 && actualSize >= 0 && declaredSize != actualSize
    }
  }

  private struct VersionedAnalysisSummary: Decodable {
    let schemaVersion: Int
    let contract: String
    let status: String
    let dioCacheQuickCheck: String
    let recognizedPayloads: Int
    let cacheRows: Int
    let uniqueCachePayloads: Int
    let rawCacheExported: Bool
    let profilePayloadsDetectedNotExported: Int
    let movieLibrary: Int
    let seriesLibrary: Int
    let watchedMovies: Int
    let movieWatchlist: Int
    let favoriteShows: Int
    let favoriteMovies: Int
    let watchEvents: Int
    let watchEventsWithTitles: Int
    let episodeCacheRows: Int
    let episodeCacheUnique: Int
    let sqliteDatabases: Int
    let sqliteIntegrity: [String: Int]
    let plistFiles: Int
    let csvSpreadsheetEscapedCells: [String: [CSVSpreadsheetEscape]]
    let parserStatus: String

    enum CodingKeys: String, CodingKey {
      case schemaVersion = "schema_version"
      case contract
      case status
      case dioCacheQuickCheck = "dio_cache_quick_check"
      case recognizedPayloads = "recognized_payloads"
      case cacheRows = "cache_rows"
      case uniqueCachePayloads = "unique_cache_payloads"
      case rawCacheExported = "raw_cache_exported"
      case profilePayloadsDetectedNotExported = "profile_payloads_detected_not_exported"
      case movieLibrary = "movie_library"
      case seriesLibrary = "series_library"
      case watchedMovies = "watched_movies"
      case movieWatchlist = "movie_watchlist"
      case favoriteShows = "favorite_shows"
      case favoriteMovies = "favorite_movies"
      case watchEvents = "watch_events"
      case watchEventsWithTitles = "watch_events_with_titles"
      case episodeCacheRows = "episode_cache_rows"
      case episodeCacheUnique = "episode_cache_unique"
      case sqliteDatabases = "sqlite_databases"
      case sqliteIntegrity = "sqlite_integrity"
      case plistFiles = "plist_files"
      case csvSpreadsheetEscapedCells = "csv_spreadsheet_escaped_cells"
      case parserStatus = "parser_status"
    }

    var hasPlausibleContractValues: Bool {
      let counts = [
        recognizedPayloads, cacheRows, uniqueCachePayloads,
        profilePayloadsDetectedNotExported, watchEvents, movieLibrary, watchedMovies,
        movieWatchlist, watchEventsWithTitles, seriesLibrary, favoriteMovies, favoriteShows,
        episodeCacheRows, episodeCacheUnique, sqliteDatabases, plistFiles,
      ]
      guard
        dioCacheQuickCheck == "ok",
        ["recognized", "empty"].contains(parserStatus),
        !rawCacheExported,
        counts.allSatisfy({ $0 >= 0 }),
        sqliteIntegrity.values.allSatisfy({ $0 >= 0 }),
        watchEventsWithTitles <= watchEvents,
        episodeCacheUnique <= episodeCacheRows
      else {
        return false
      }

      var escapeCount = 0
      for (filename, coordinates) in csvSpreadsheetEscapedCells {
        guard
          !filename.isEmpty,
          filename.utf8.count <= RecoveryOutputValidator.maximumCSVMetadataStringBytes,
          escapeCount <= RecoveryOutputValidator.maximumCSVSpreadsheetEscapes - coordinates.count
        else {
          return false
        }
        escapeCount += coordinates.count
        guard coordinates.allSatisfy(\.isPlausible) else {
          return false
        }
      }
      return true
    }

    var summary: AnalysisSummary {
      AnalysisSummary(
        seriesLibrary: seriesLibrary,
        watchedMovies: watchedMovies,
        movieWatchlist: movieWatchlist,
        favoriteShows: favoriteShows,
        favoriteMovies: favoriteMovies,
        watchEvents: watchEvents,
        watchEventsWithTitles: watchEventsWithTitles,
        episodeCacheUnique: episodeCacheUnique,
        parserStatus: parserStatus
      )
    }
  }

  private struct CSVSpreadsheetEscape: Decodable {
    let row: Int
    let field: String

    var isPlausible: Bool {
      row >= 1 && row <= RecoveryOutputValidator.maximumAnalysisCSVRows
        && !field.isEmpty
        && field.utf8.count <= RecoveryOutputValidator.maximumCSVMetadataStringBytes
    }
  }

  private enum ArtifactFormat {
    case json
    case csv(String)
    case utf8Lines
    case markdown
    case html
    case pdf
  }

  private struct ExpectedArtifact {
    let id: String
    let relativePath: String
    let maximumBytes: Int64
    let format: ArtifactFormat
    let captureAll: Bool
  }

  private static func expectedArtifacts(pdfStatus: String) -> [ExpectedArtifact] {
    var expected = [
      ExpectedArtifact(
        id: "extraction_run_state",
        relativePath: "metadata/run_state.json",
        maximumBytes: maximumStateBytes,
        format: .json,
        captureAll: true
      ),
      ExpectedArtifact(
        id: "extraction_inventory",
        relativePath: "metadata/inventory.csv",
        maximumBytes: maximumInventoryBytes,
        format: .csv(
          "file_id,domain,relative_path,declared_size,actual_size,size_match,mtime,sha256"
        ),
        captureAll: true
      ),
      ExpectedArtifact(
        id: "extraction_summary",
        relativePath: "metadata/summary.json",
        maximumBytes: maximumAnalysisSummaryBytes,
        format: .json,
        captureAll: true
      ),
      ExpectedArtifact(
        id: "extraction_domains",
        relativePath: "metadata/domains.txt",
        maximumBytes: maximumDomainsBytes,
        format: .utf8Lines,
        captureAll: true
      ),
      ExpectedArtifact(
        id: "analysis_summary",
        relativePath: "analysis/analysis_summary.json",
        maximumBytes: maximumAnalysisSummaryBytes,
        format: .json,
        captureAll: true
      ),
      csvArtifact(
        "cache_index",
        "cache_index.csv",
        "source_id,status_code,bytes,sha256,duplicate_of,json_valid,shape,data_type,object_count,exported_file"
      ),
      csvArtifact(
        "movie_library",
        "movie_library.csv",
        "uuid,name,imdb_id,first_release_date,library_status,watched_at,followed_at,runtime_seconds,genres,filters,is_watched,created_at,updated_at"
      ),
      csvArtifact(
        "watch_events",
        "watch_events.csv",
        "uuid,entity_type,type,watched_at,runtime,created_at,updated_at"
      ),
      csvArtifact(
        "episode_cache",
        "episode_cache.csv",
        "source_id,episode_id,show_id,show_name,season,episode,episode_name,air_date,seen,seen_date,is_watched,runtime"
      ),
      csvArtifact(
        "sqlite_integrity",
        "sqlite_integrity.csv",
        "relative_path,bytes,quick_check,schema_objects"
      ),
      csvArtifact(
        "plist_key_inventory",
        "plist_key_inventory.csv",
        "relative_path,format,top_level_keys"
      ),
      csvArtifact(
        "series_library",
        "series_library.csv",
        "uuid,series_id,name,country,is_ended,followed_at,last_watch_date,filters,created_at,updated_at"
      ),
      csvArtifact(
        "watched_movies",
        "watched_movies.csv",
        "uuid,name,imdb_id,first_release_date,library_status,watched_at,followed_at,runtime_seconds,genres,filters,is_watched,created_at,updated_at"
      ),
      csvArtifact(
        "movie_watchlist",
        "movie_watchlist.csv",
        "uuid,name,imdb_id,first_release_date,library_status,watched_at,followed_at,runtime_seconds,genres,filters,is_watched,created_at,updated_at"
      ),
      csvArtifact(
        "favorite_shows",
        "favorite_shows.csv",
        "uuid,id,name,type,status,created_at,watched_episode_count,aired_episode_count,is_followed,is_up_to_date"
      ),
      csvArtifact(
        "favorite_movies",
        "favorite_movies.csv",
        "uuid,id,name,type,status,created_at,watched_episode_count,aired_episode_count,is_followed,is_up_to_date"
      ),
      csvArtifact(
        "episode_cache_unique",
        "episode_cache_unique.csv",
        "source_id,episode_id,show_id,show_name,season,episode,episode_name,air_date,seen,seen_date,is_watched,runtime"
      ),
      csvArtifact(
        "watch_events_named",
        "watch_events_named.csv",
        "uuid,movie_name,entity_type,type,watched_at,runtime,created_at,updated_at"
      ),
      csvArtifact(
        "trailer_references",
        "trailer_references.csv",
        "title,trailer_name,runtime_seconds,url,thumbnail_url"
      ),
      csvArtifact(
        "media_url_inventory",
        "media_url_inventory.csv",
        "kind,host,field_path,url"
      ),
      csvArtifact(
        "image_cache_references",
        "image_cache_references.csv",
        "cache_id,category,intended_filename,declared_bytes,width,height,source_url,cached_request_url,valid_till,touched"
      ),
      ExpectedArtifact(
        id: "markdown_report",
        relativePath: "analysis/TVTime-Recovered-Data.md",
        maximumBytes: maximumArtifactBytes,
        format: .markdown,
        captureAll: false
      ),
      ExpectedArtifact(
        id: "html_report",
        relativePath: "analysis/TVTime-Recovered-Data.html",
        maximumBytes: maximumArtifactBytes,
        format: .html,
        captureAll: false
      ),
    ]
    if pdfStatus == "generated" {
      expected.append(
        ExpectedArtifact(
          id: "pdf_report",
          relativePath: "analysis/TVTime-Recovered-Data.pdf",
          maximumBytes: maximumArtifactBytes,
          format: .pdf,
          captureAll: false
        )
      )
    }
    return expected
  }

  private static func csvArtifact(
    _ id: String,
    _ filename: String,
    _ header: String
  ) -> ExpectedArtifact {
    ExpectedArtifact(
      id: id,
      relativePath: "analysis/\(filename)",
      maximumBytes: maximumArtifactBytes,
      format: .csv(header),
      captureAll: false
    )
  }

  private static func expectedDirectoryMembership(
    directory: String,
    artifacts: [ExpectedArtifact],
    additionalNames: Set<String>
  ) throws -> Set<String> {
    let prefix = "\(directory)/"
    var result = additionalNames
    for artifact in artifacts where artifact.relativePath.hasPrefix(prefix) {
      try Task.checkCancellation()
      let name = String(artifact.relativePath.dropFirst(prefix.count))
      guard !name.isEmpty, !name.contains("/"), !name.contains("\\") else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      guard result.insert(name).inserted else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
    }
    guard
      !result.isEmpty,
      result.allSatisfy({ !$0.isEmpty && !$0.contains("/") && !$0.contains("\\") })
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    return result
  }

  private static func validateExtractionRunState(
    _ data: Data,
    expected: ExtractionSummary
  ) throws -> ValidatedExtractionRunState {
    guard data.count <= maximumStateBytes else {
      throw RecoveryOutputValidationError.unreadableCompletionMarker
    }
    let state: ExtractionRunState
    do {
      try validateExactExtractionRunStateSchema(data)
      state = try JSONDecoder().decode(ExtractionRunState.self, from: data)
    } catch is CancellationError {
      throw CancellationError()
    } catch {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    guard
      state.schemaVersion == recoveryStateSchemaVersion,
      state.contract == extractionRunStateContract,
      state.status == "complete",
      isPlausibleTimestamp(state.completedUTC),
      state.summary == expected,
      state.sourceSnapshot.isPlausible,
      state.sourceSnapshot.rawTree.files == expected.filesExtracted,
      state.sourceSnapshot.rawTree.byteSize == expected.bytesExtracted
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    return ValidatedExtractionRunState(
      sourceSnapshot: state.sourceSnapshot,
      completedUTC: state.completedUTC
    )
  }

  private static func validateExtractionSummary(
    _ data: Data,
    domainsData: Data,
    expected: ExtractionSummary,
    expectedCompletedUTC: String,
    expectedSelectedDeclaredBytes: Int64,
    expectedSizeDiscrepancies: [ExtractionSizeDiscrepancy]
  ) throws {
    guard data.count <= maximumAnalysisSummaryBytes else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    let state: ExtractionMetadataSummary
    do {
      try validateExactExtractionSummarySchema(data)
      state = try JSONDecoder().decode(ExtractionMetadataSummary.self, from: data)
    } catch is CancellationError {
      throw CancellationError()
    } catch {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    let expectedDomainsText = state.domains.joined(separator: "\n") + "\n"
    guard
      state.bundleID == "com.tozelabs.tvshowtime",
      state.summary == expected,
      state.failures.isEmpty,
      !state.decryptedManifestIncluded,
      state.completedUTC == expectedCompletedUTC,
      state.selectedDeclaredBytes == expectedSelectedDeclaredBytes,
      isPlausibleTimestamp(state.completedUTC),
      !state.domains.isEmpty,
      state.domains == Array(Set(state.domains)).sorted(),
      state.domains.contains("AppDomain-com.tozelabs.tvshowtime"),
      state.domains.allSatisfy({
        $0 == "AppDomain-com.tozelabs.tvshowtime"
          || $0.hasPrefix("AppDomainPlugin-com.tozelabs.tvshowtime.")
      }),
      state.domains.allSatisfy(isSafeInventoryDomain),
      state.sizeDiscrepancies.allSatisfy(\.isPlausible),
      state.sizeDiscrepancies == expectedSizeDiscrepancies,
      domainsData == Data(expectedDomainsText.utf8)
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
  }

  private static func declaredByteTotal(_ entries: [InventoryEntry]) throws -> Int64 {
    var total: Int64 = 0
    for entry in entries {
      try Task.checkCancellation()
      let addition = total.addingReportingOverflow(entry.declaredByteSize)
      guard !addition.overflow else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      total = addition.partialValue
    }
    return total
  }

  private static func isPlausibleTimestamp(_ value: String) -> Bool {
    !value.isEmpty
      && value.count <= 64
      && value.contains("T")
      && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }

  private static func validateAnalysisSummary(
    _ data: Data,
    expected: AnalysisSummary
  ) throws {
    guard data.count <= maximumAnalysisSummaryBytes else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    let state: VersionedAnalysisSummary
    do {
      try validateExactAnalysisSummarySchema(data)
      state = try JSONDecoder().decode(VersionedAnalysisSummary.self, from: data)
    } catch is CancellationError {
      throw CancellationError()
    } catch {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    guard
      state.schemaVersion == recoveryStateSchemaVersion,
      state.contract == analysisSummaryContract,
      state.status == "complete",
      state.hasPlausibleContractValues,
      state.summary == expected
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
  }

  private struct InventoryEntry {
    let domain: String
    let relativePath: String
    let declaredByteSize: Int64
    let relativeRawPath: String
    let byteSize: Int64
    let sha256: String

    var sizeDiscrepancy: ExtractionSizeDiscrepancy? {
      guard declaredByteSize != byteSize else {
        return nil
      }
      return ExtractionSizeDiscrepancy(
        domain: domain,
        relativePath: relativePath,
        declaredSize: declaredByteSize,
        actualSize: byteSize
      )
    }
  }

  private static func validateRawTree(
    entries: [InventoryEntry],
    expected: SourceSnapshot,
    beneath extractionRoot: DirectoryAnchor
  ) throws {
    var totalBytes: Int64 = 0
    for entry in entries {
      try Task.checkCancellation()
      let addition = totalBytes.addingReportingOverflow(entry.byteSize)
      guard !addition.overflow else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      totalBytes = addition.partialValue
    }
    guard
      entries.count == expected.rawTree.files,
      totalBytes == expected.rawTree.byteSize
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }

    let rawRootURL = try artifactURL(relativePath: "raw", beneath: extractionRoot.url)
    let rawRootDescriptor = try openArtifactNoFollow(
      at: rawRootURL,
      beneath: extractionRoot,
      expectedType: .directory
    )
    defer { Darwin.close(rawRootDescriptor) }
    let rawRoot = DirectoryAnchor(url: rawRootURL, descriptor: rawRootDescriptor)
    let expectedPaths = entries.map(\.relativeRawPath)
    let expectedDirectories = try expectedRawDirectories(entries)
    let expectedMembership = RawTreeMembership(
      directories: expectedDirectories,
      files: expectedPaths
    )
    guard try enumerateRawTree(beneath: rawRoot) == expectedMembership else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }

    var hasher = SHA256()
    hasher.update(data: rawTreeDigestPrefix)
    for entry in entries {
      try Task.checkCancellation()
      let rawFile = try artifactURL(relativePath: entry.relativeRawPath, beneath: rawRoot.url)
      let snapshot = try readRegularFile(
        at: rawFile,
        beneath: rawRoot,
        maximumBytes: entry.byteSize,
        captureAll: false,
        allowEmpty: true
      )
      guard snapshot.byteSize == entry.byteSize, snapshot.sha256 == entry.sha256 else {
        throw RecoveryOutputValidationError.artifactIntegrityFailure
      }
      let pathData = Data(entry.relativeRawPath.utf8)
      update(&hasher, withBigEndian: UInt64(pathData.count))
      hasher.update(data: pathData)
      update(&hasher, withBigEndian: UInt64(entry.byteSize))
      guard let contentDigest = dataFromLowercaseHex(entry.sha256) else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      hasher.update(data: contentDigest)
    }

    // Repeat every byte check as well as membership so a replacement racing an
    // earlier file read cannot become a trusted native result.
    for entry in entries {
      try Task.checkCancellation()
      let rawFile = try artifactURL(relativePath: entry.relativeRawPath, beneath: rawRoot.url)
      let snapshot = try readRegularFile(
        at: rawFile,
        beneath: rawRoot,
        maximumBytes: entry.byteSize,
        captureAll: false,
        allowEmpty: true
      )
      guard snapshot.byteSize == entry.byteSize, snapshot.sha256 == entry.sha256 else {
        throw RecoveryOutputValidationError.artifactIntegrityFailure
      }
    }
    guard try enumerateRawTree(beneath: rawRoot) == expectedMembership else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    let observedDigest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
    guard observedDigest == expected.rawTree.sha256 else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    let inventoryURL = try artifactURL(
      relativePath: "metadata/inventory.csv",
      beneath: extractionRoot.url
    )
    let inventoryAfter = try readRegularFile(
      at: inventoryURL,
      beneath: extractionRoot,
      maximumBytes: maximumInventoryBytes,
      captureAll: false
    )
    guard
      inventoryAfter.byteSize == expected.inventory.byteSize,
      inventoryAfter.sha256 == expected.inventory.sha256
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
  }

  private static func parseInventory(_ data: Data) throws -> [InventoryEntry] {
    let records = try parseCSVForValidation(
      data,
      maximumRecords: RecoveryOutputContractLimits.maximumInventoryRows + 1
    )
    let header = [
      "file_id", "domain", "relative_path", "declared_size", "actual_size", "size_match",
      "mtime", "sha256",
    ]
    guard records.first == header else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    var seenPaths = Set<Data>()
    var entries: [InventoryEntry] = []
    var previousDomainBytes: Data?
    var previousRelativePathBytes: Data?
    for record in records.dropFirst() {
      try Task.checkCancellation()
      guard record.count == header.count else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      let fileID = record[0]
      let domain = record[1]
      let relativePath = record[2]
      guard
        fileID.count == 40,
        fileID.allSatisfy({ $0.isASCII && $0.isHexDigit && !$0.isUppercase }),
        isSafeInventoryDomain(domain),
        isSafeInventoryRelativePath(relativePath),
        let declaredSize = canonicalNonnegativeInt64(record[3]),
        let actualSize = canonicalNonnegativeInt64(record[4]),
        record[5] == (declaredSize == actualSize ? "True" : "False"),
        isLowercaseSHA256(record[7])
      else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      let rawPath = "\(domain)/\(relativePath)"
      let domainBytes = Data(domain.utf8)
      let relativePathBytes = Data(relativePath.utf8)
      var rawPathBytes = domainBytes
      rawPathBytes.append(0x2F)
      rawPathBytes.append(relativePathBytes)
      guard seenPaths.insert(rawPathBytes).inserted else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      if let previousDomainBytes, let previousRelativePathBytes {
        let domainIsEarlier = domainBytes.lexicographicallyPrecedes(previousDomainBytes)
        let relativePathIsEarlier =
          domainBytes == previousDomainBytes
          && relativePathBytes.lexicographicallyPrecedes(previousRelativePathBytes)
        guard !domainIsEarlier && !relativePathIsEarlier else {
          throw RecoveryOutputValidationError.incompleteOutput
        }
      }
      previousDomainBytes = domainBytes
      previousRelativePathBytes = relativePathBytes
      entries.append(
        InventoryEntry(
          domain: domain,
          relativePath: relativePath,
          declaredByteSize: declaredSize,
          relativeRawPath: rawPath,
          byteSize: actualSize,
          sha256: record[7]
        )
      )
    }
    return entries
  }

  private static func expectedRawDirectories(_ entries: [InventoryEntry]) throws -> [String] {
    var directories = Set<String>()
    for entry in entries {
      try Task.checkCancellation()
      let components = entry.relativeRawPath.split(separator: "/").dropLast()
      for count in 1...components.count {
        directories.insert(components.prefix(count).joined(separator: "/"))
      }
    }
    return directories.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
  }

  static func parseCSVForValidation(_ data: Data, maximumRecords: Int) throws -> [[String]] {
    guard maximumRecords > 0 else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    try Task.checkCancellation()
    return try data.withUnsafeBytes { rawBuffer in
      try parseCSV(
        rawBuffer.bindMemory(to: UInt8.self),
        maximumRecords: maximumRecords
      )
    }
  }

  private static func parseCSV(
    _ bytes: UnsafeBufferPointer<UInt8>,
    maximumRecords: Int
  ) throws -> [[String]] {
    var records = [[[UInt8]]]()
    var record = [[UInt8]]()
    var field = [UInt8]()
    var index = 0
    var inQuotes = false
    var closedQuote = false
    var endedWithRecordSeparator = false
    var nextCancellationCheck = 0

    func finishField() {
      record.append(field)
      field.removeAll(keepingCapacity: true)
      closedQuote = false
    }

    func finishRecord() throws {
      guard records.count < maximumRecords else {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      finishField()
      records.append(record)
      record.removeAll(keepingCapacity: true)
      endedWithRecordSeparator = true
    }

    while index < bytes.count {
      if index >= nextCancellationCheck {
        try Task.checkCancellation()
        nextCancellationCheck = index + 64 * 1024
      }
      let byte = bytes[index]
      if inQuotes {
        if byte == 0x22 {
          if index + 1 < bytes.count, bytes[index + 1] == 0x22 {
            field.append(0x22)
            index += 2
            continue
          }
          inQuotes = false
          closedQuote = true
          index += 1
          continue
        }
        field.append(byte)
        index += 1
        continue
      }

      if closedQuote, byte != 0x2C, byte != 0x0A, byte != 0x0D {
        throw RecoveryOutputValidationError.incompleteOutput
      }
      switch byte {
      case 0x22:
        guard field.isEmpty else {
          throw RecoveryOutputValidationError.incompleteOutput
        }
        inQuotes = true
        endedWithRecordSeparator = false
        index += 1
      case 0x2C:
        finishField()
        endedWithRecordSeparator = false
        index += 1
      case 0x0A:
        try finishRecord()
        index += 1
      case 0x0D:
        guard index + 1 < bytes.count, bytes[index + 1] == 0x0A else {
          throw RecoveryOutputValidationError.incompleteOutput
        }
        try finishRecord()
        index += 2
      default:
        field.append(byte)
        endedWithRecordSeparator = false
        index += 1
      }
    }
    guard !inQuotes else {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    if !endedWithRecordSeparator || !record.isEmpty || !field.isEmpty {
      try finishRecord()
    }
    var decodedRecords = [[String]]()
    decodedRecords.reserveCapacity(records.count)
    for rawRecord in records {
      try Task.checkCancellation()
      let decodedRecord = try rawRecord.map { rawField in
        guard let value = String(bytes: rawField, encoding: .utf8) else {
          throw RecoveryOutputValidationError.incompleteOutput
        }
        return value
      }
      decodedRecords.append(decodedRecord)
    }
    return decodedRecords
  }

  private static func canonicalNonnegativeInt64(_ value: String) -> Int64? {
    guard
      !value.isEmpty,
      value.allSatisfy(\.isNumber),
      let parsed = Int64(value),
      parsed >= 0,
      String(parsed) == value
    else { return nil }
    return parsed
  }

  private static func isSafeInventoryDomain(_ value: String) -> Bool {
    !value.isEmpty && !value.contains("/") && !value.contains("\\")
      && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }

  private static func isSafeInventoryRelativePath(_ value: String) -> Bool {
    let components = value.split(separator: "/", omittingEmptySubsequences: false)
    return !value.isEmpty && !value.hasPrefix("/") && !value.contains("\\")
      && components.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
      && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }

  private static func isLowercaseSHA256(_ value: String) -> Bool {
    value.count == 64
      && value.allSatisfy { $0.isASCII && $0.isHexDigit && !$0.isUppercase }
  }

  private static func dataFromLowercaseHex(_ value: String) -> Data? {
    guard isLowercaseSHA256(value) else { return nil }
    var result = Data(capacity: value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
      result.append(byte)
      index = next
    }
    return result
  }

  private static func update(_ hasher: inout SHA256, withBigEndian value: UInt64) {
    var encoded = value.bigEndian
    withUnsafeBytes(of: &encoded) { hasher.update(bufferPointer: $0) }
  }

  private struct RawTreeMembership: Equatable {
    var directories = [String]()
    var files = [String]()
  }

  private static func requireEmptyDirectory(_ descriptor: Int32) throws {
    let duplicate = Darwin.dup(descriptor)
    guard duplicate >= 0, let directory = Darwin.fdopendir(duplicate) else {
      if duplicate >= 0 { Darwin.close(duplicate) }
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    defer { Darwin.closedir(directory) }
    errno = 0
    while let entry = Darwin.readdir(directory) {
      try Task.checkCancellation()
      let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
        let capacity = MemoryLayout.size(ofValue: pointer.pointee)
        return pointer.withMemoryRebound(to: CChar.self, capacity: capacity) {
          String(validatingCString: $0)
        }
      }
      guard let name else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      if name == "." || name == ".." {
        errno = 0
        continue
      }
      throw RecoveryOutputValidationError.incompleteOutput
    }
    guard errno == 0 else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
  }

  private static func requireExactSubdirectoryMembership(
    _ directoryDescriptor: Int32,
    expectedNames: Set<String>
  ) throws {
    guard
      !expectedNames.isEmpty,
      expectedNames.allSatisfy({ !$0.isEmpty && !$0.contains("/") && !$0.contains("\\") })
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }

    var directoryBefore = stat()
    guard Darwin.fstat(directoryDescriptor, &directoryBefore) == 0 else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    try require(directoryBefore, type: .directory)
    try requirePrivate(directoryBefore, descriptor: directoryDescriptor)

    let duplicate = Darwin.dup(directoryDescriptor)
    guard duplicate >= 0, let directory = Darwin.fdopendir(duplicate) else {
      if duplicate >= 0 { Darwin.close(duplicate) }
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    defer { Darwin.closedir(directory) }

    var observed = Set<String>()
    errno = 0
    while let entry = Darwin.readdir(directory) {
      try Task.checkCancellation()
      let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
        let capacity = MemoryLayout.size(ofValue: pointer.pointee)
        return pointer.withMemoryRebound(to: CChar.self, capacity: capacity) {
          String(validatingCString: $0)
        }
      }
      guard let name else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      if name == "." || name == ".." {
        errno = 0
        continue
      }
      guard
        !name.contains("/"),
        expectedNames.contains(name),
        observed.insert(name).inserted
      else {
        throw RecoveryOutputValidationError.incompleteOutput
      }

      var metadata = stat()
      let status = name.withCString { pointer in
        Darwin.fstatat(directoryDescriptor, pointer, &metadata, AT_SYMLINK_NOFOLLOW)
      }
      guard status == 0 else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      guard metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }

      let childDescriptor = name.withCString { pointer in
        Darwin.openat(
          directoryDescriptor,
          pointer,
          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
      }
      guard childDescriptor >= 0 else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      var openedMetadata = stat()
      do {
        guard
          Darwin.fstat(childDescriptor, &openedMetadata) == 0,
          openedMetadata.st_dev == metadata.st_dev,
          openedMetadata.st_ino == metadata.st_ino
        else {
          throw RecoveryOutputValidationError.artifactIntegrityFailure
        }
        try require(openedMetadata, type: .directory)
        try requirePrivate(openedMetadata, descriptor: childDescriptor)
      } catch {
        Darwin.close(childDescriptor)
        throw error
      }
      Darwin.close(childDescriptor)

      var pathAfter = stat()
      let afterStatus = name.withCString { pointer in
        Darwin.fstatat(directoryDescriptor, pointer, &pathAfter, AT_SYMLINK_NOFOLLOW)
      }
      guard
        afterStatus == 0,
        pathAfter.st_dev == openedMetadata.st_dev,
        pathAfter.st_ino == openedMetadata.st_ino,
        pathAfter.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
      else {
        throw RecoveryOutputValidationError.artifactIntegrityFailure
      }
      errno = 0
    }
    guard errno == 0, observed == expectedNames else {
      throw RecoveryOutputValidationError.incompleteOutput
    }

    var directoryAfter = stat()
    guard
      Darwin.fstat(directoryDescriptor, &directoryAfter) == 0,
      sameSnapshot(directoryBefore, directoryAfter)
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    try requirePrivate(directoryAfter, descriptor: directoryDescriptor)
  }

  private static func requireExactRegularFileMembership(
    at directoryURL: URL,
    beneath root: DirectoryAnchor,
    expectedNames: Set<String>
  ) throws {
    guard
      !expectedNames.isEmpty,
      expectedNames.allSatisfy({ !$0.isEmpty && !$0.contains("/") && !$0.contains("\\") })
    else {
      throw RecoveryOutputValidationError.incompleteOutput
    }

    let directoryDescriptor = try openArtifactNoFollow(
      at: directoryURL,
      beneath: root,
      expectedType: .directory
    )
    defer { Darwin.close(directoryDescriptor) }
    var directoryBefore = stat()
    guard Darwin.fstat(directoryDescriptor, &directoryBefore) == 0 else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    try require(directoryBefore, type: .directory)
    try requirePrivate(directoryBefore, descriptor: directoryDescriptor)

    let duplicate = Darwin.dup(directoryDescriptor)
    guard duplicate >= 0, let directory = Darwin.fdopendir(duplicate) else {
      if duplicate >= 0 { Darwin.close(duplicate) }
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    defer { Darwin.closedir(directory) }

    var observed = Set<String>()
    errno = 0
    while let entry = Darwin.readdir(directory) {
      try Task.checkCancellation()
      let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
        let capacity = MemoryLayout.size(ofValue: pointer.pointee)
        return pointer.withMemoryRebound(to: CChar.self, capacity: capacity) {
          String(validatingCString: $0)
        }
      }
      guard let name else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      if name == "." || name == ".." {
        errno = 0
        continue
      }
      guard
        !name.contains("/"),
        expectedNames.contains(name),
        observed.insert(name).inserted
      else {
        throw RecoveryOutputValidationError.incompleteOutput
      }

      var metadata = stat()
      let status = name.withCString { pointer in
        Darwin.fstatat(directoryDescriptor, pointer, &metadata, AT_SYMLINK_NOFOLLOW)
      }
      guard status == 0, metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
        throw RecoveryOutputValidationError.incompleteOutput
      }

      let childDescriptor = name.withCString { pointer in
        Darwin.openat(directoryDescriptor, pointer, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
      }
      guard childDescriptor >= 0 else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      var openedMetadata = stat()
      do {
        guard
          Darwin.fstat(childDescriptor, &openedMetadata) == 0,
          openedMetadata.st_dev == metadata.st_dev,
          openedMetadata.st_ino == metadata.st_ino
        else {
          throw RecoveryOutputValidationError.artifactIntegrityFailure
        }
        try require(openedMetadata, type: .regularFile)
        try requirePrivate(openedMetadata, descriptor: childDescriptor)
      } catch {
        Darwin.close(childDescriptor)
        throw error
      }
      Darwin.close(childDescriptor)

      var pathAfter = stat()
      let afterStatus = name.withCString { pointer in
        Darwin.fstatat(directoryDescriptor, pointer, &pathAfter, AT_SYMLINK_NOFOLLOW)
      }
      guard
        afterStatus == 0,
        pathAfter.st_dev == openedMetadata.st_dev,
        pathAfter.st_ino == openedMetadata.st_ino,
        pathAfter.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG)
      else {
        throw RecoveryOutputValidationError.artifactIntegrityFailure
      }
      errno = 0
    }
    guard errno == 0, observed == expectedNames else {
      throw RecoveryOutputValidationError.incompleteOutput
    }

    var directoryAfter = stat()
    guard
      Darwin.fstat(directoryDescriptor, &directoryAfter) == 0,
      sameSnapshot(directoryBefore, directoryAfter)
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    try requirePrivate(directoryAfter, descriptor: directoryDescriptor)
    let pathAfterDescriptor = try openArtifactNoFollow(
      at: directoryURL,
      beneath: root,
      expectedType: .directory
    )
    defer { Darwin.close(pathAfterDescriptor) }
    var pathAfter = stat()
    guard
      Darwin.fstat(pathAfterDescriptor, &pathAfter) == 0,
      pathAfter.st_dev == directoryAfter.st_dev,
      pathAfter.st_ino == directoryAfter.st_ino
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    try require(pathAfter, type: .directory)
    try requirePrivate(pathAfter, descriptor: pathAfterDescriptor)
  }

  private static func enumerateRawTree(beneath root: DirectoryAnchor) throws -> RawTreeMembership {
    let rootDescriptor = try reopenDirectoryDescriptor(root.descriptor)
    defer { Darwin.close(rootDescriptor) }
    var rootMetadata = stat()
    guard Darwin.fstat(rootDescriptor, &rootMetadata) == 0 else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    try require(rootMetadata, type: .directory)
    try requirePrivate(rootMetadata, descriptor: rootDescriptor)
    var result = RawTreeMembership()
    try enumerateRawTree(
      directoryDescriptor: rootDescriptor,
      prefix: "",
      result: &result
    )
    result.directories.sort { $0.utf8.lexicographicallyPrecedes($1.utf8) }
    result.files.sort { $0.utf8.lexicographicallyPrecedes($1.utf8) }
    return result
  }

  private static func enumerateRawTree(
    directoryDescriptor: Int32,
    prefix: String,
    result: inout RawTreeMembership
  ) throws {
    let duplicate = Darwin.dup(directoryDescriptor)
    guard duplicate >= 0, let directory = Darwin.fdopendir(duplicate) else {
      if duplicate >= 0 { Darwin.close(duplicate) }
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    defer { Darwin.closedir(directory) }
    errno = 0
    while let entry = Darwin.readdir(directory) {
      try Task.checkCancellation()
      let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
        let capacity = MemoryLayout.size(ofValue: pointer.pointee)
        return pointer.withMemoryRebound(to: CChar.self, capacity: capacity) {
          String(validatingCString: $0)
        }
      }
      guard let name, name != ".", name != "..", !name.contains("/") else {
        if name == "." || name == ".." { continue }
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      var metadata = stat()
      let status = name.withCString { pointer in
        Darwin.fstatat(directoryDescriptor, pointer, &metadata, AT_SYMLINK_NOFOLLOW)
      }
      guard status == 0 else {
        throw RecoveryOutputValidationError.artifactIntegrityFailure
      }
      try requirePrivateMode(metadata)
      let relativePath = prefix.isEmpty ? name : "\(prefix)/\(name)"
      let fileType = metadata.st_mode & mode_t(S_IFMT)
      if fileType == mode_t(S_IFREG) {
        let child = name.withCString { pointer in
          Darwin.openat(directoryDescriptor, pointer, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard child >= 0 else {
          throw RecoveryOutputValidationError.unsafeArtifact
        }
        defer { Darwin.close(child) }
        var openedMetadata = stat()
        guard
          Darwin.fstat(child, &openedMetadata) == 0,
          openedMetadata.st_dev == metadata.st_dev,
          openedMetadata.st_ino == metadata.st_ino
        else {
          throw RecoveryOutputValidationError.artifactIntegrityFailure
        }
        try requirePrivate(openedMetadata, descriptor: child)
        result.files.append(relativePath)
      } else if fileType == mode_t(S_IFDIR) {
        result.directories.append(relativePath)
        let child = name.withCString { pointer in
          Darwin.openat(
            directoryDescriptor,
            pointer,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
          )
        }
        guard child >= 0 else {
          throw RecoveryOutputValidationError.unsafeArtifact
        }
        defer { Darwin.close(child) }
        var openedMetadata = stat()
        guard
          Darwin.fstat(child, &openedMetadata) == 0,
          openedMetadata.st_dev == metadata.st_dev,
          openedMetadata.st_ino == metadata.st_ino
        else {
          throw RecoveryOutputValidationError.artifactIntegrityFailure
        }
        try requirePrivate(openedMetadata, descriptor: child)
        try enumerateRawTree(
          directoryDescriptor: child,
          prefix: relativePath,
          result: &result
        )
      } else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      errno = 0
    }
    guard errno == 0 else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
  }

  private enum ExpectedType {
    case directory
    case regularFile
  }

  private struct DirectoryAnchor {
    let url: URL
    let descriptor: Int32
  }

  private static func openValidationRoot(_ outputDirectory: URL) throws -> DirectoryAnchor {
    let rootURL = try normalizedValidationRoot(outputDirectory)
    let anchorURL: URL
    let components: [String]
    if let containerAnchor = validationAnchor(containing: rootURL) {
      anchorURL = containerAnchor
      guard let relative = relativePathComponents(of: rootURL, beneath: containerAnchor) else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      components = relative
    } else {
      // Preserve the strict root walk for non-sandboxed and synthetic paths.
      anchorURL = URL(fileURLWithPath: "/", isDirectory: true)
      components = rootURL.path.split(separator: "/").map(String.init)
    }
    let initialDescriptor = anchorURL.path.withCString { pointer in
      Darwin.open(pointer, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
    }
    guard initialDescriptor >= 0 else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }

    var descriptor = initialDescriptor
    do {
      for component in components {
        let nextDescriptor = component.withCString { pointer in
          Darwin.openat(
            descriptor,
            pointer,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
          )
        }
        guard nextDescriptor >= 0 else {
          if errno == ENOENT {
            throw RecoveryOutputValidationError.missingArtifact
          }
          throw RecoveryOutputValidationError.unsafeArtifact
        }

        var metadata = stat()
        guard Darwin.fstat(nextDescriptor, &metadata) == 0 else {
          Darwin.close(nextDescriptor)
          throw RecoveryOutputValidationError.unsafeArtifact
        }
        do {
          try require(metadata, type: .directory)
        } catch {
          Darwin.close(nextDescriptor)
          throw error
        }
        Darwin.close(descriptor)
        descriptor = nextDescriptor
      }

      var rootMetadata = stat()
      guard Darwin.fstat(descriptor, &rootMetadata) == 0 else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      try require(rootMetadata, type: .directory)
      try requirePrivate(rootMetadata, descriptor: descriptor)
      return DirectoryAnchor(url: rootURL, descriptor: descriptor)
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  static func validationAnchor(
    containing outputDirectory: URL,
    applicationSupportDirectory: URL = FileManager.default.urls(
      for: .applicationSupportDirectory,
      in: .userDomainMask
    )[0],
    sandboxHomeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
  ) -> URL? {
    let applicationSupport = applicationSupportDirectory.standardizedFileURL
    let containerHome =
      applicationSupport
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .standardizedFileURL
    guard
      containerHome.path.contains("/Library/Containers/"),
      containerHome == sandboxHomeDirectory.standardizedFileURL,
      relativePathComponents(of: outputDirectory.standardizedFileURL, beneath: containerHome) != nil
    else {
      return nil
    }
    return containerHome
  }

  private static func relativePathComponents(of destination: URL, beneath anchor: URL) -> [String]?
  {
    let destinationPath = destination.standardizedFileURL.path
    let anchorPath = anchor.standardizedFileURL.path
    if anchorPath == "/" {
      guard destinationPath.hasPrefix("/") else { return nil }
      return destinationPath.split(separator: "/").map(String.init)
    }
    guard destinationPath == anchorPath || destinationPath.hasPrefix(anchorPath + "/") else {
      return nil
    }
    guard destinationPath != anchorPath else { return [] }
    return destinationPath.dropFirst(anchorPath.count + 1).split(separator: "/").map(String.init)
  }

  private static func normalizedValidationRoot(_ outputDirectory: URL) throws -> URL {
    guard outputDirectory.isFileURL else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    let path = try lexicallyNormalizedAbsolutePath(outputDirectory.path)
    let standardized = URL(fileURLWithPath: path)

    for mapping in trustedDarwinRootAliases
    where path == mapping.alias || path.hasPrefix(mapping.alias + "/") {
      var aliasMetadata = stat()
      let status = mapping.alias.withCString { pointer in
        Darwin.lstat(pointer, &aliasMetadata)
      }
      guard
        status == 0,
        aliasMetadata.st_uid == 0,
        aliasMetadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFLNK)
      else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }

      let destination: String
      do {
        destination = try FileManager.default.destinationOfSymbolicLink(atPath: mapping.alias)
      } catch {
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      guard
        destination == mapping.target
          || destination == String(mapping.target.dropFirst())
      else {
        throw RecoveryOutputValidationError.unsafeArtifact
      }

      let suffix = String(path.dropFirst(mapping.alias.count))
      return URL(fileURLWithPath: mapping.target + suffix)
    }
    return standardized
  }

  private static func lexicallyNormalizedAbsolutePath(_ path: String) throws -> String {
    guard path.hasPrefix("/"), !path.contains("\0") else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    var normalizedComponents = [Substring]()
    for component in path.split(separator: "/", omittingEmptySubsequences: true) {
      if component == "." {
        continue
      }
      if component == ".." {
        guard !normalizedComponents.isEmpty else {
          throw RecoveryOutputValidationError.unsafeArtifact
        }
        normalizedComponents.removeLast()
        continue
      }
      normalizedComponents.append(component)
    }
    return "/" + normalizedComponents.joined(separator: "/")
  }

  private static func requireAbsent(relativePath: String, beneath root: DirectoryAnchor) throws {
    let components = try safeRelativeComponents(relativePath)
    guard let finalComponent = components.last else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    let parentDescriptor: Int32
    let closesParentDescriptor: Bool
    if components.count == 1 {
      parentDescriptor = root.descriptor
      closesParentDescriptor = false
    } else {
      let parentPath = components.dropLast().joined(separator: "/")
      let parentURL = try artifactURL(relativePath: parentPath, beneath: root.url)
      parentDescriptor = try openArtifactNoFollow(
        at: parentURL,
        beneath: root,
        expectedType: .directory
      )
      closesParentDescriptor = true
    }
    defer {
      if closesParentDescriptor {
        Darwin.close(parentDescriptor)
      }
    }

    var metadata = stat()
    let result = finalComponent.withCString { pointer in
      Darwin.fstatat(parentDescriptor, pointer, &metadata, AT_SYMLINK_NOFOLLOW)
    }
    if result == 0 {
      throw RecoveryOutputValidationError.incompleteOutput
    }
    guard errno == ENOENT else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
  }

  private static func validateRelativeArtifact(
    _ relativePath: String,
    beneath root: DirectoryAnchor,
    expectedType: ExpectedType
  ) throws {
    let artifact = try artifactURL(relativePath: relativePath, beneath: root.url)
    try validatePath(artifact, beneath: root, expectedType: expectedType)
  }

  private static func artifactURL(relativePath: String, beneath root: URL) throws -> URL {
    let components = try safeRelativeComponents(relativePath)
    let candidate = components.reduce(root) { partial, component in
      partial.appendingPathComponent(component, isDirectory: false)
    }
    guard candidate.path.hasPrefix(root.path + "/") else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    return candidate
  }

  private static func safeRelativeComponents(_ relativePath: String) throws -> [String] {
    let components = relativePath.split(separator: "/", omittingEmptySubsequences: false)
      .map(String.init)
    guard
      !components.isEmpty,
      components.allSatisfy({
        !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\0")
      })
    else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    return components
  }

  private static func validatePath(
    _ candidate: URL,
    beneath root: DirectoryAnchor,
    expectedType: ExpectedType
  ) throws {
    let descriptor = try openArtifactNoFollow(
      at: candidate,
      beneath: root,
      expectedType: expectedType
    )
    Darwin.close(descriptor)
  }

  private static func require(_ metadata: stat, type: ExpectedType) throws {
    let fileType = metadata.st_mode & mode_t(S_IFMT)
    let expectedFileType: mode_t =
      switch type {
      case .directory:
        mode_t(S_IFDIR)
      case .regularFile:
        mode_t(S_IFREG)
      }
    guard fileType == expectedFileType else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
  }

  private static func requirePrivateMode(_ metadata: stat) throws {
    guard metadata.st_uid == Darwin.geteuid(), metadata.st_mode & mode_t(0o077) == 0 else {
      throw RecoveryOutputValidationError.insecurePermissions
    }
  }

  private static func requireNoExtendedACL(_ descriptor: Int32) throws {
    errno = 0
    guard let acl = Darwin.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
      guard errno == ENOENT else {
        throw RecoveryOutputValidationError.insecurePermissions
      }
      return
    }
    defer { _ = Darwin.acl_free(UnsafeMutableRawPointer(acl)) }

    var entry: acl_entry_t?
    errno = 0
    let result = Darwin.acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry)
    if result == 0 {
      throw RecoveryOutputValidationError.insecurePermissions
    }
    guard result == -1, errno == EINVAL || errno == ENOENT else {
      throw RecoveryOutputValidationError.insecurePermissions
    }
  }

  private static func requirePrivate(_ metadata: stat, descriptor: Int32) throws {
    try requirePrivateMode(metadata)
    try requireNoExtendedACL(descriptor)
  }

  private struct RegularFileSnapshot {
    let byteSize: Int64
    let sha256: String
    let prefix: Data
    let data: Data?
  }

  private static func readRegularFile(
    at url: URL,
    beneath root: DirectoryAnchor,
    maximumBytes: Int64,
    captureAll: Bool,
    allowEmpty: Bool = false
  ) throws -> RegularFileSnapshot {
    let descriptor = try openRegularFileNoFollow(at: url, beneath: root)
    defer { Darwin.close(descriptor) }

    var before = stat()
    guard Darwin.fstat(descriptor, &before) == 0 else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    try require(before, type: .regularFile)
    try requirePrivate(before, descriptor: descriptor)
    guard
      before.st_size >= (allowEmpty ? 0 : 1),
      before.st_size <= maximumBytes
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }

    var hasher = SHA256()
    var prefix = Data()
    var captured = captureAll ? Data() : nil
    if captureAll {
      captured?.reserveCapacity(Int(before.st_size))
    }
    var bytesRead: Int64 = 0
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while true {
      try Task.checkCancellation()
      let count = Darwin.read(descriptor, &buffer, buffer.count)
      if count > 0 {
        let chunk = Data(buffer.prefix(Int(count)))
        hasher.update(data: chunk)
        bytesRead += Int64(count)
        guard bytesRead <= maximumBytes, bytesRead <= before.st_size else {
          throw RecoveryOutputValidationError.artifactIntegrityFailure
        }
        if prefix.count < 512 {
          prefix.append(chunk.prefix(512 - prefix.count))
        }
        captured?.append(chunk)
        continue
      }
      if count == -1, errno == EINTR {
        continue
      }
      guard count == 0 else {
        throw RecoveryOutputValidationError.artifactIntegrityFailure
      }
      break
    }

    var after = stat()
    guard
      Darwin.fstat(descriptor, &after) == 0,
      sameSnapshot(before, after),
      bytesRead == before.st_size
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    try requirePrivate(after, descriptor: descriptor)

    let pathAfterDescriptor = try openRegularFileNoFollow(at: url, beneath: root)
    defer { Darwin.close(pathAfterDescriptor) }
    var pathAfter = stat()
    guard
      Darwin.fstat(pathAfterDescriptor, &pathAfter) == 0,
      pathAfter.st_dev == after.st_dev,
      pathAfter.st_ino == after.st_ino
    else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    try require(pathAfter, type: .regularFile)
    try requirePrivate(pathAfter, descriptor: pathAfterDescriptor)

    let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
    return RegularFileSnapshot(
      byteSize: bytesRead,
      sha256: digest,
      prefix: prefix,
      data: captured
    )
  }

  private static func openRegularFileNoFollow(
    at url: URL,
    beneath root: DirectoryAnchor
  ) throws -> Int32 {
    try openArtifactNoFollow(at: url, beneath: root, expectedType: .regularFile)
  }

  private static func reopenDirectoryDescriptor(_ descriptor: Int32) throws -> Int32 {
    let reopened = ".".withCString { pointer in
      Darwin.openat(
        descriptor,
        pointer,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
      )
    }
    guard reopened >= 0 else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    var originalMetadata = stat()
    var reopenedMetadata = stat()
    guard
      Darwin.fstat(descriptor, &originalMetadata) == 0,
      Darwin.fstat(reopened, &reopenedMetadata) == 0,
      originalMetadata.st_dev == reopenedMetadata.st_dev,
      originalMetadata.st_ino == reopenedMetadata.st_ino
    else {
      Darwin.close(reopened)
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
    do {
      try require(reopenedMetadata, type: .directory)
      try requirePrivate(reopenedMetadata, descriptor: reopened)
    } catch {
      Darwin.close(reopened)
      throw error
    }
    return reopened
  }

  private static func openArtifactNoFollow(
    at url: URL,
    beneath root: DirectoryAnchor,
    expectedType: ExpectedType
  ) throws -> Int32 {
    let standardizedRoot = root.url
    let standardizedURL = url
    guard
      standardizedRoot.isFileURL,
      standardizedURL.isFileURL,
      standardizedURL == standardizedRoot
        || standardizedURL.path.hasPrefix(standardizedRoot.path + "/")
    else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }

    var rootDescriptorMetadata = stat()
    guard Darwin.fstat(root.descriptor, &rootDescriptorMetadata) == 0 else {
      throw RecoveryOutputValidationError.unsafeArtifact
    }
    try require(rootDescriptorMetadata, type: .directory)
    try requirePrivate(rootDescriptorMetadata, descriptor: root.descriptor)

    if standardizedURL == standardizedRoot {
      try require(rootDescriptorMetadata, type: expectedType)
      return try reopenDirectoryDescriptor(root.descriptor)
    }

    let relative = standardizedURL.path.dropFirst(standardizedRoot.path.count + 1)
    let components = try safeRelativeComponents(String(relative))

    var parentDescriptor = try reopenDirectoryDescriptor(root.descriptor)
    defer { Darwin.close(parentDescriptor) }
    for (index, component) in components.enumerated() {
      try Task.checkCancellation()
      let isFinal = index == components.count - 1
      let componentType: ExpectedType = isFinal ? expectedType : .directory
      let directoryFlag: Int32 =
        switch componentType {
        case .directory:
          O_DIRECTORY
        case .regularFile:
          0
        }
      let flags =
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | directoryFlag
      let nextDescriptor = component.withCString { pointer in
        Darwin.openat(parentDescriptor, pointer, flags)
      }
      guard nextDescriptor >= 0 else {
        if errno == ENOENT {
          throw RecoveryOutputValidationError.missingArtifact
        }
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      var metadata = stat()
      guard Darwin.fstat(nextDescriptor, &metadata) == 0 else {
        Darwin.close(nextDescriptor)
        throw RecoveryOutputValidationError.unsafeArtifact
      }
      do {
        try require(metadata, type: componentType)
        try requirePrivate(metadata, descriptor: nextDescriptor)
      } catch {
        Darwin.close(nextDescriptor)
        throw error
      }
      if isFinal {
        return nextDescriptor
      }
      Darwin.close(parentDescriptor)
      parentDescriptor = nextDescriptor
    }
    throw RecoveryOutputValidationError.unsafeArtifact
  }

  private static func sameSnapshot(_ before: stat, _ after: stat) -> Bool {
    before.st_dev == after.st_dev
      && before.st_ino == after.st_ino
      && before.st_size == after.st_size
      && before.st_mode == after.st_mode
      && before.st_uid == after.st_uid
      && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec
      && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec
      && before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec
      && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
  }

  private static func validateFormat(_ prefix: Data, expected: ArtifactFormat) throws {
    let valid: Bool =
      switch expected {
      case .json:
        prefix.drop(while: { $0 == 0x20 || $0 == 0x09 || $0 == 0x0A || $0 == 0x0D }).first
          == 0x7B
      case .csv(let header):
        prefix.starts(with: Data((header + "\n").utf8))
          || prefix.starts(with: Data((header + "\r\n").utf8))
      case .utf8Lines:
        hasValidUTF8Lines(prefix)
      case .markdown:
        prefix.starts(with: Data("# TV Time recovered-data report\n".utf8))
      case .html:
        prefix.starts(with: Data("<!doctype html>".utf8))
      case .pdf:
        prefix.starts(with: Data("%PDF-".utf8))
      }
    guard valid else {
      throw RecoveryOutputValidationError.artifactIntegrityFailure
    }
  }

  private static func hasValidUTF8Lines(_ data: Data) -> Bool {
    guard
      let text = String(data: data, encoding: .utf8),
      text.hasSuffix("\n"),
      !text.contains("\r")
    else {
      return false
    }
    let content = text.dropLast()
    return !content.isEmpty
      && content.split(separator: "\n", omittingEmptySubsequences: false).allSatisfy {
        !$0.isEmpty
          && !$0.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
      }
  }
}

enum RecoveryOutputValidationError: LocalizedError {
  case invalidSummary
  case missingArtifact
  case unsafeArtifact
  case insecurePermissions
  case unreadableCompletionMarker
  case incompleteOutput
  case artifactIntegrityFailure

  var errorDescription: String? {
    switch self {
    case .invalidSummary:
      "The recovery helper returned an incomplete result summary. Preserve the output for review."
    case .missingArtifact:
      "A required private recovery artifact is unavailable. Preserve the output for review."
    case .unsafeArtifact:
      "A required recovery artifact failed its local path or file-type safety check. Preserve the output for review."
    case .insecurePermissions:
      "A required recovery artifact was not private to this user account. Preserve the output for review."
    case .unreadableCompletionMarker:
      "The private recovery completion marker could not be read safely. Preserve the output for review."
    case .incompleteOutput:
      "The private recovery output does not satisfy the v0.2 completion contract. Preserve it and use a fresh output folder for another attempt."
    case .artifactIntegrityFailure:
      "A private recovery artifact did not match its completion record. Preserve the output and use a fresh output folder for another attempt."
    }
  }
}
