import CryptoKit
import Darwin
import Foundation

@testable import TVTimeRecoveryCore

enum TestFixtures {
  static func backupReceipt(
    backupRegularFiles: Int64 = 100,
    backupLogicalBytes: Int64 = 120_000,
    rootDevice: UInt64 = 7,
    rootInode: UInt64 = 11
  ) -> BackupReceipt {
    BackupReceipt(
      rootDevice: rootDevice,
      rootInode: rootInode,
      backupRegularFiles: backupRegularFiles,
      backupLogicalBytes: backupLogicalBytes,
      manifestPlist: receiptFileSnapshot(
        size: 4_096,
        inode: 12,
        sha256Character: "a"
      ),
      manifestDatabase: receiptFileSnapshot(
        size: 8_000,
        inode: 13,
        sha256Character: "b"
      ),
      statusPlist: receiptFileSnapshot(
        size: 1_024,
        inode: 14,
        sha256Character: "c"
      )
    )
  }

  private static func receiptFileSnapshot(
    size: Int64,
    inode: UInt64,
    sha256Character: Character
  ) -> BackupReceipt.FileSnapshot {
    BackupReceipt.FileSnapshot(
      mode: 0o100600,
      size: size,
      modifiedNanoseconds: 1_752_832_800_000_000_000,
      changedNanoseconds: 1_752_832_800_000_000_001,
      device: 7,
      inode: inode,
      sha256: String(repeating: sha256Character, count: 64)
    )
  }

  static func preflight(
    encrypted: Bool = true,
    snapshotState: String = "finished",
    backupRegularFiles: Int = 100,
    backupLogicalBytes: Int64 = 120_000,
    manifestDatabaseBytes: Int64 = 8_000,
    destinationFreeBytes: Int64 = 1_000_000,
    minimumWorkingBytes: Int64 = 500_000,
    hasMinimumSpace: Bool = true
  ) -> PreflightSummary {
    PreflightSummary(
      encrypted: encrypted,
      snapshotState: snapshotState,
      backupDate: "2026-07-18T10:00:00Z",
      backupRegularFiles: backupRegularFiles,
      backupLogicalBytes: backupLogicalBytes,
      manifestDatabaseBytes: manifestDatabaseBytes,
      destinationFreeBytes: destinationFreeBytes,
      minimumWorkingBytes: minimumWorkingBytes,
      hasMinimumSpace: hasMinimumSpace,
      warnings: []
    )
  }

  static func extraction(
    filesExpected: Int = 7,
    filesExtracted: Int = 7,
    bytesExtracted: Int64 = 12_345,
    selectedDeclaredBytes: Int64 = 12_345,
    sizeDiscrepancyCount: Int = 0
  ) -> ExtractionSummary {
    ExtractionSummary(
      filesExpected: filesExpected,
      filesExtracted: filesExtracted,
      bytesExtracted: bytesExtracted,
      selectedDeclaredBytes: selectedDeclaredBytes,
      sizeDiscrepancyCount: sizeDiscrepancyCount
    )
  }

  static func analysis(
    seriesLibrary: Int = 3,
    watchedMovies: Int = 2,
    movieWatchlist: Int = 1,
    favoriteShows: Int = 1,
    favoriteMovies: Int = 1,
    watchEvents: Int = 5,
    watchEventsWithTitles: Int = 3,
    episodeCacheUnique: Int = 2,
    parserStatus: String = "recognized"
  ) -> AnalysisSummary {
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

  static func report(
    imageCacheReferences: Int = 12,
    trailerReferences: Int = 7,
    mediaURLs: Int = 19,
    pdfStatus: String = "generated",
    pdfOmissionReason: String? = nil
  ) -> ReportSummary {
    ReportSummary(
      imageCacheReferences: imageCacheReferences,
      trailerReferences: trailerReferences,
      mediaURLs: mediaURLs,
      pdfStatus: pdfStatus,
      pdfOmissionReason: pdfOmissionReason
    )
  }

  static func artifacts(
    extractionDirectory: String = RecoveryArtifacts.expectedExtractionDirectory,
    report: String = RecoveryArtifacts.expectedReport,
    visualReport: String = RecoveryArtifacts.expectedVisualReport,
    pdfReport: String? = RecoveryArtifacts.expectedPDFReport,
    analysisDirectory: String = RecoveryArtifacts.expectedAnalysisDirectory,
    recoveryState: String = RecoveryArtifacts.expectedRecoveryState
  ) -> RecoveryArtifacts {
    RecoveryArtifacts(
      extractionDirectory: extractionDirectory,
      report: report,
      visualReport: visualReport,
      pdfReport: pdfReport,
      analysisDirectory: analysisDirectory,
      recoveryState: recoveryState
    )
  }

  static func summary(
    preflight: PreflightSummary = preflight(),
    extraction: ExtractionSummary = extraction(),
    analysis: AnalysisSummary = analysis(),
    report: ReportSummary = report(),
    artifacts: RecoveryArtifacts = artifacts()
  ) -> RecoverySummary {
    RecoverySummary(
      preflight: preflight,
      extraction: extraction,
      analysis: analysis,
      report: report,
      artifacts: artifacts
    )
  }

  static func omittedPDFSummary(reason: String = "PDF rendering was unavailable.")
    -> RecoverySummary
  {
    summary(
      report: report(pdfStatus: "omitted", pdfOmissionReason: reason),
      artifacts: artifacts(pdfReport: nil)
    )
  }

  static func event<Payload: Encodable>(
    type: String,
    payload: Payload,
    sequence: Int = 1,
    protocolVersion: Int = HelperProtocolV3.version
  ) throws -> HelperEvent {
    let envelope = EventEnvelope(
      protocolVersion: protocolVersion,
      sequence: sequence,
      type: type,
      payload: payload
    )
    return try HelperEventDecoder.decode(JSONEncoder().encode(envelope))
  }

  static func preflightCompletionEvent(
    _ preflight: PreflightSummary = preflight(),
    backupReceipt: BackupReceipt? = nil,
    sequence: Int = 2
  ) throws -> HelperEvent {
    let receipt =
      backupReceipt
      ?? TestFixtures.backupReceipt(
        backupRegularFiles: Int64(preflight.backupRegularFiles),
        backupLogicalBytes: preflight.backupLogicalBytes
      )
    return try event(
      type: "completed",
      payload: PreflightCompletionPayload(preflight: preflight, backupReceipt: receipt),
      sequence: sequence
    )
  }

  static func recoveryCompletionEvent(
    _ summary: RecoverySummary = summary(),
    sequence: Int = 3
  ) throws -> HelperEvent {
    try event(type: "completed", payload: summary, sequence: sequence)
  }

  static func makePrivateOutput(
    at root: URL,
    summary: RecoverySummary = summary(),
    markerOverrides: [String: Any] = [:]
  ) throws {
    let fileManager = FileManager.default
    let extraction = root.appendingPathComponent(RecoveryArtifacts.expectedExtractionDirectory)
    let analysis = root.appendingPathComponent(RecoveryArtifacts.expectedAnalysisDirectory)
    let metadata = extraction.appendingPathComponent("metadata", isDirectory: true)
    let manifest = extraction.appendingPathComponent("manifest", isDirectory: true)
    let raw = extraction.appendingPathComponent("raw", isDirectory: true)
    try fileManager.createDirectory(at: analysis, withIntermediateDirectories: true)
    try fileManager.createDirectory(at: metadata, withIntermediateDirectories: false)
    try fileManager.createDirectory(at: manifest, withIntermediateDirectories: false)
    try fileManager.createDirectory(at: raw, withIntermediateDirectories: false)
    try setMode(0o700, at: root)
    try setMode(0o700, at: extraction)
    try setMode(0o700, at: analysis)
    try setMode(0o700, at: metadata)
    try setMode(0o700, at: manifest)
    try setMode(0o700, at: raw)

    let sourceSnapshot = try makeSyntheticRawTree(
      beneath: extraction,
      fileCount: summary.extraction.filesExtracted,
      byteCount: summary.extraction.bytesExtracted
    )

    try writePrivate(
      try JSONSerialization.data(
        withJSONObject: extractionRunState(summary.extraction, sourceSnapshot: sourceSnapshot),
        options: [.sortedKeys]
      ),
      at: metadata.appendingPathComponent("run_state.json")
    )
    try writePrivate(
      try JSONSerialization.data(
        withJSONObject: extractionMetadataSummary(summary.extraction),
        options: [.sortedKeys]
      ),
      at: metadata.appendingPathComponent("summary.json")
    )
    try writePrivate(
      Data("AppDomain-com.tozelabs.tvshowtime\n".utf8),
      at: metadata.appendingPathComponent("domains.txt")
    )
    try writePrivate(
      try JSONSerialization.data(
        withJSONObject: analysisState(summary.analysis),
        options: [.sortedKeys]
      ),
      at: analysis.appendingPathComponent("analysis_summary.json")
    )

    for (filename, header) in csvHeaders {
      try writePrivate(
        Data((header + "\r\n").utf8),
        at: analysis.appendingPathComponent(filename)
      )
    }
    try writePrivate(
      Data("# TV Time recovered-data report\n\nSynthetic private report.\n".utf8),
      at: root.appendingPathComponent(summary.artifacts.report)
    )
    try writePrivate(
      Data("<!doctype html><title>Recovered data</title>\n".utf8),
      at: root.appendingPathComponent(summary.artifacts.visualReport)
    )
    if let pdfReport = summary.artifacts.pdfReport {
      try writePrivate(Data("%PDF-1.4\n".utf8), at: root.appendingPathComponent(pdfReport))
    }

    var artifactBindings = try boundArtifacts.map { id, path in
      try artifactBinding(id: id, relativePath: path, extraction: extraction)
    }
    if summary.report.pdfStatus == "generated" {
      artifactBindings.append(
        try artifactBinding(
          id: "pdf_report",
          relativePath: "analysis/TVTime-Recovered-Data.pdf",
          extraction: extraction
        )
      )
    }

    var reportAggregate: [String: Any] = [
      "image_cache_references": summary.report.imageCacheReferences,
      "trailer_references": summary.report.trailerReferences,
      "media_urls": summary.report.mediaURLs,
      "pdf_status": summary.report.pdfStatus,
    ]
    if let reason = summary.report.pdfOmissionReason {
      reportAggregate["pdf_omission_reason"] = reason
    }
    var marker: [String: Any] = [
      "schema_version": 2,
      "contract": "tvtime-recovery-state-v0.2",
      "status": "complete",
      "completed_utc": "2026-07-18T10:00:00+00:00",
      "pdf": [
        "status": summary.report.pdfStatus,
        "artifact_id": summary.report.pdfStatus == "generated" ? "pdf_report" : NSNull(),
      ],
      "source_snapshot": sourceSnapshot,
      "aggregates": [
        "extraction": extractionAggregate(summary.extraction),
        "analysis": analysisAggregate(summary.analysis),
        "report": reportAggregate,
      ],
      "artifacts": artifactBindings,
    ]
    marker.merge(markerOverrides) { _, replacement in replacement }
    let markerData = try JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys])
    try writePrivate(markerData, at: root.appendingPathComponent(summary.artifacts.recoveryState))
  }

  static func rewriteRecoveryMarker(
    beneath root: URL,
    transform: (inout [String: Any]) throws -> Void
  ) throws {
    let markerURL = root.appendingPathComponent(RecoveryArtifacts.expectedRecoveryState)
    let value = try JSONSerialization.jsonObject(with: Data(contentsOf: markerURL))
    guard var marker = value as? [String: Any] else {
      throw POSIXFixtureError(operation: "decode-marker", code: EINVAL)
    }
    try transform(&marker)
    try writePrivate(
      JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys]),
      at: markerURL
    )
  }

  static func refreshArtifactBinding(beneath root: URL, id: String) throws {
    let extraction = root.appendingPathComponent(RecoveryArtifacts.expectedExtractionDirectory)
    try rewriteRecoveryMarker(beneath: root) { marker in
      guard var artifacts = marker["artifacts"] as? [[String: Any]],
        let index = artifacts.firstIndex(where: { $0["id"] as? String == id }),
        let relativePath = artifacts[index]["relative_path"] as? String
      else {
        throw POSIXFixtureError(operation: "find-artifact", code: ENOENT)
      }
      artifacts[index] = try artifactBinding(
        id: id,
        relativePath: relativePath,
        extraction: extraction
      )
      marker["artifacts"] = artifacts
    }
  }

  static func writePrivate(_ data: Data, at url: URL) throws {
    try data.write(to: url, options: .atomic)
    try setMode(0o600, at: url)
  }

  static func setMode(_ mode: mode_t, at url: URL) throws {
    guard Darwin.chmod(url.path, mode) == 0 else {
      throw POSIXFixtureError(operation: "chmod", code: errno)
    }
  }

  private static let boundArtifacts: [(String, String)] = [
    ("extraction_run_state", "metadata/run_state.json"),
    ("extraction_inventory", "metadata/inventory.csv"),
    ("extraction_summary", "metadata/summary.json"),
    ("extraction_domains", "metadata/domains.txt"),
    ("analysis_summary", "analysis/analysis_summary.json"),
    ("cache_index", "analysis/cache_index.csv"),
    ("movie_library", "analysis/movie_library.csv"),
    ("watch_events", "analysis/watch_events.csv"),
    ("episode_cache", "analysis/episode_cache.csv"),
    ("sqlite_integrity", "analysis/sqlite_integrity.csv"),
    ("plist_key_inventory", "analysis/plist_key_inventory.csv"),
    ("series_library", "analysis/series_library.csv"),
    ("watched_movies", "analysis/watched_movies.csv"),
    ("movie_watchlist", "analysis/movie_watchlist.csv"),
    ("favorite_shows", "analysis/favorite_shows.csv"),
    ("favorite_movies", "analysis/favorite_movies.csv"),
    ("episode_cache_unique", "analysis/episode_cache_unique.csv"),
    ("watch_events_named", "analysis/watch_events_named.csv"),
    ("trailer_references", "analysis/trailer_references.csv"),
    ("media_url_inventory", "analysis/media_url_inventory.csv"),
    ("image_cache_references", "analysis/image_cache_references.csv"),
    ("markdown_report", "analysis/TVTime-Recovered-Data.md"),
    ("html_report", "analysis/TVTime-Recovered-Data.html"),
  ]

  private static let csvHeaders: [(String, String)] = [
    (
      "cache_index.csv",
      "source_id,status_code,bytes,sha256,duplicate_of,json_valid,shape,data_type,object_count,exported_file"
    ),
    (
      "movie_library.csv",
      "uuid,name,imdb_id,first_release_date,library_status,watched_at,followed_at,runtime_seconds,genres,filters,is_watched,created_at,updated_at"
    ),
    (
      "watch_events.csv",
      "uuid,entity_type,type,watched_at,runtime,created_at,updated_at"
    ),
    (
      "episode_cache.csv",
      "source_id,episode_id,show_id,show_name,season,episode,episode_name,air_date,seen,seen_date,is_watched,runtime"
    ),
    ("sqlite_integrity.csv", "relative_path,bytes,quick_check,schema_objects"),
    ("plist_key_inventory.csv", "relative_path,format,top_level_keys"),
    (
      "series_library.csv",
      "uuid,series_id,name,country,is_ended,followed_at,last_watch_date,filters,created_at,updated_at"
    ),
    (
      "watched_movies.csv",
      "uuid,name,imdb_id,first_release_date,library_status,watched_at,followed_at,runtime_seconds,genres,filters,is_watched,created_at,updated_at"
    ),
    (
      "movie_watchlist.csv",
      "uuid,name,imdb_id,first_release_date,library_status,watched_at,followed_at,runtime_seconds,genres,filters,is_watched,created_at,updated_at"
    ),
    (
      "favorite_shows.csv",
      "uuid,id,name,type,status,created_at,watched_episode_count,aired_episode_count,is_followed,is_up_to_date"
    ),
    (
      "favorite_movies.csv",
      "uuid,id,name,type,status,created_at,watched_episode_count,aired_episode_count,is_followed,is_up_to_date"
    ),
    (
      "episode_cache_unique.csv",
      "source_id,episode_id,show_id,show_name,season,episode,episode_name,air_date,seen,seen_date,is_watched,runtime"
    ),
    (
      "watch_events_named.csv",
      "uuid,movie_name,entity_type,type,watched_at,runtime,created_at,updated_at"
    ),
    (
      "trailer_references.csv",
      "title,trailer_name,runtime_seconds,url,thumbnail_url"
    ),
    ("media_url_inventory.csv", "kind,host,field_path,url"),
    (
      "image_cache_references.csv",
      "cache_id,category,intended_filename,declared_bytes,width,height,source_url,cached_request_url,valid_till,touched"
    ),
  ]

  private static func artifactBinding(
    id: String,
    relativePath: String,
    extraction: URL
  ) throws -> [String: Any] {
    let data = try Data(contentsOf: extraction.appendingPathComponent(relativePath))
    return [
      "id": id,
      "relative_path": relativePath,
      "bytes": data.count,
      "sha256": SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
    ]
  }

  private static func extractionRunState(
    _ value: ExtractionSummary,
    sourceSnapshot: [String: Any]
  ) -> [String: Any] {
    var state = extractionAggregate(value)
    state["schema_version"] = 2
    state["contract"] = "tvtime-extraction-run-state-v0.2"
    state["status"] = "complete"
    state["completed_utc"] = "2026-07-18T10:00:00+00:00"
    state["source_snapshot"] = sourceSnapshot
    return state
  }

  private static func extractionMetadataSummary(_ value: ExtractionSummary) -> [String: Any] {
    [
      "bundle_id": "com.tozelabs.tvshowtime",
      "domains": ["AppDomain-com.tozelabs.tvshowtime"],
      "files_expected": value.filesExpected,
      "files_extracted": value.filesExtracted,
      "failures": [],
      "bytes_extracted": value.bytesExtracted,
      "selected_declared_bytes": value.selectedDeclaredBytes,
      "size_discrepancies": [],
      "decrypted_manifest_included": false,
      "completed_utc": "2026-07-18T10:00:00+00:00",
    ]
  }

  private static func makeSyntheticRawTree(
    beneath extraction: URL,
    fileCount: Int,
    byteCount: Int64
  ) throws -> [String: Any] {
    guard
      fileCount >= 0,
      byteCount >= 0,
      fileCount != 0 || byteCount == 0,
      fileCount == 0 || byteCount <= Int64(Int.max)
    else {
      throw POSIXFixtureError(operation: "synthetic-raw-tree", code: EINVAL)
    }
    let raw = extraction.appendingPathComponent("raw", isDirectory: true)
    let domainName = "AppDomain-com.tozelabs.tvshowtime"
    let domain = raw.appendingPathComponent(domainName, isDirectory: true)
    let documents = domain.appendingPathComponent("Documents", isDirectory: true)
    try FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
    try setMode(0o700, at: domain)
    try setMode(0o700, at: documents)

    var rows = [String]()
    var rawHasher = SHA256()
    rawHasher.update(data: Data("tvtime-raw-tree-digest-v0.2\0".utf8))
    let baseSize = fileCount == 0 ? 0 : byteCount / Int64(fileCount)
    let remainder = fileCount == 0 ? 0 : byteCount % Int64(fileCount)
    for index in 0..<fileCount {
      let size = baseSize + (Int64(index) < remainder ? 1 : 0)
      let filename = String(format: "Synthetic-%04d.bin", index + 1)
      let relativePath = "Documents/\(filename)"
      let relativeRawPath = "\(domainName)/\(relativePath)"
      let payload = Data(repeating: UInt8((index % 251) + 1), count: Int(size))
      let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
      try writePrivate(payload, at: documents.appendingPathComponent(filename))
      let fileID = String(format: "%040llx", UInt64(index + 1))
      rows.append(
        "\(fileID),\(domainName),\(relativePath),\(size),\(size),True,2026-01-01T00:00:00Z,\(digest)"
      )

      let pathData = Data(relativeRawPath.utf8)
      update(&rawHasher, withBigEndian: UInt64(pathData.count))
      rawHasher.update(data: pathData)
      update(&rawHasher, withBigEndian: UInt64(size))
      rawHasher.update(data: dataFromHex(digest))
    }

    let header =
      "file_id,domain,relative_path,declared_size,actual_size,size_match,mtime,sha256"
    let inventory = Data(([header] + rows).joined(separator: "\r\n").appending("\r\n").utf8)
    try writePrivate(inventory, at: extraction.appendingPathComponent("metadata/inventory.csv"))
    return [
      "contract": "tvtime-source-snapshot-v0.2",
      "inventory": [
        "bytes": inventory.count,
        "sha256": SHA256.hash(data: inventory).map { String(format: "%02x", $0) }.joined(),
      ],
      "raw_tree": [
        "files": fileCount,
        "bytes": byteCount,
        "sha256": rawHasher.finalize().map { String(format: "%02x", $0) }.joined(),
      ],
    ]
  }

  private static func update(_ hasher: inout SHA256, withBigEndian value: UInt64) {
    var encoded = value.bigEndian
    withUnsafeBytes(of: &encoded) { hasher.update(bufferPointer: $0) }
  }

  private static func dataFromHex(_ value: String) -> Data {
    var data = Data(capacity: value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      data.append(UInt8(value[index..<next], radix: 16)!)
      index = next
    }
    return data
  }

  private static func extractionAggregate(_ value: ExtractionSummary) -> [String: Any] {
    [
      "files_expected": value.filesExpected,
      "files_extracted": value.filesExtracted,
      "bytes_extracted": value.bytesExtracted,
      "selected_declared_bytes": value.selectedDeclaredBytes,
      "size_discrepancy_count": value.sizeDiscrepancyCount,
    ]
  }

  private static func analysisState(_ value: AnalysisSummary) -> [String: Any] {
    var state = analysisAggregate(value)
    state["schema_version"] = 2
    state["contract"] = "tvtime-analysis-summary-v0.2"
    state["status"] = "complete"
    state["dio_cache_quick_check"] = "ok"
    state["recognized_payloads"] = 1
    state["cache_rows"] = 1
    state["unique_cache_payloads"] = 1
    state["raw_cache_exported"] = false
    state["profile_payloads_detected_not_exported"] = 0
    state["movie_library"] = value.watchedMovies + value.movieWatchlist
    state["episode_cache_rows"] = value.episodeCacheUnique
    state["sqlite_databases"] = 1
    state["sqlite_integrity"] = ["synthetic.sqlite": 1]
    state["plist_files"] = 0
    state["csv_spreadsheet_escaped_cells"] = [String: Any]()
    return state
  }

  private static func analysisAggregate(_ value: AnalysisSummary) -> [String: Any] {
    [
      "series_library": value.seriesLibrary,
      "watched_movies": value.watchedMovies,
      "movie_watchlist": value.movieWatchlist,
      "favorite_shows": value.favoriteShows,
      "favorite_movies": value.favoriteMovies,
      "watch_events": value.watchEvents,
      "watch_events_with_titles": value.watchEventsWithTitles,
      "episode_cache_unique": value.episodeCacheUnique,
      "parser_status": value.parserStatus,
    ]
  }
}

private struct EventEnvelope<Payload: Encodable>: Encodable {
  let protocolVersion: Int
  let sequence: Int
  let type: String
  let payload: Payload
}

private struct PreflightCompletionPayload: Encodable {
  let preflight: PreflightSummary
  let backupReceipt: BackupReceipt

  enum CodingKeys: String, CodingKey {
    case preflight
    case backupReceipt = "backup_receipt"
  }
}

private struct POSIXFixtureError: Error {
  let operation: String
  let code: Int32
}

extension FileManager {
  func makeTestDirectory() throws -> URL {
    let root = temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try createDirectory(at: root, withIntermediateDirectories: false)
    try TestFixtures.setMode(0o700, at: root)
    return root
  }
}
