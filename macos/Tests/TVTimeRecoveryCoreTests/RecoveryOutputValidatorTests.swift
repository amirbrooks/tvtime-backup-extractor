import CryptoKit
import Darwin
import Foundation
import Testing

@testable import TVTimeRecoveryCore

@Suite(.serialized)
final class RecoveryOutputValidatorTests {
  private var temporaryDirectories: [URL] = []

  deinit {
    for directory in temporaryDirectories {
      try? FileManager.default.removeItem(at: directory)
    }
  }

  @Test
  func testValidationAnchorUsesOnlyTheContainingSandboxHome() {
    let applicationSupport = URL(
      fileURLWithPath:
        "/Users/synthetic/Library/Containers/com.example.synthetic/Data/Library/Application Support",
      isDirectory: true
    )
    let containerHome = URL(
      fileURLWithPath: "/Users/synthetic/Library/Containers/com.example.synthetic/Data",
      isDirectory: true
    )
    let containedOutput =
      applicationSupport
      .appendingPathComponent("Synthetic Extractor", isDirectory: true)
      .appendingPathComponent("Recoveries", isDirectory: true)
      .appendingPathComponent("Synthetic-Recovery", isDirectory: true)

    expectEqual(
      RecoveryOutputValidator.validationAnchor(
        containing: containedOutput,
        applicationSupportDirectory: applicationSupport,
        sandboxHomeDirectory: containerHome
      ),
      containerHome
    )
    expectNil(
      RecoveryOutputValidator.validationAnchor(
        containing: URL(fileURLWithPath: "/Users/synthetic/Documents/Other", isDirectory: true),
        applicationSupportDirectory: applicationSupport,
        sandboxHomeDirectory: containerHome
      )
    )
    expectNil(
      RecoveryOutputValidator.validationAnchor(
        containing: containedOutput,
        applicationSupportDirectory: URL(
          fileURLWithPath: "/Users/synthetic/Library/Application Support",
          isDirectory: true
        ),
        sandboxHomeDirectory: URL(fileURLWithPath: "/Users/synthetic", isDirectory: true)
      )
    )
    expectNil(
      RecoveryOutputValidator.validationAnchor(
        containing: containedOutput,
        applicationSupportDirectory: applicationSupport,
        sandboxHomeDirectory: URL(
          fileURLWithPath: "/tmp/Library/Containers/com.example.synthetic/Data",
          isDirectory: true
        )
      )
    )
  }

  @Test
  func testAcceptsCompletePrivateGeneratedAndOmittedPDFOutputs() throws {
    let generated = try makeOutput(summary: TestFixtures.summary())
    expectNoThrow(
      try RecoveryOutputValidator.validate(TestFixtures.summary(), beneath: generated)
    )

    let omittedSummary = TestFixtures.omittedPDFSummary()
    let omitted = try makeOutput(summary: omittedSummary)
    expectNoThrow(try RecoveryOutputValidator.validate(omittedSummary, beneath: omitted))
  }

  @Test
  func testCSVParserRejectsExcessRecordsAndChecksTaskCancellationBeforeParsing() async throws {
    assertValidationError(.incompleteOutput) {
      _ = try RecoveryOutputValidator.parseCSVForValidation(
        Data("header\nfirst\nsecond\n".utf8),
        maximumRecords: 2
      )
    }

    let gate = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
    let task = Task.detached {
      for await _ in gate.stream {
        break
      }
      return try RecoveryOutputValidator.parseCSVForValidation(
        Data("header\nvalue\n".utf8),
        maximumRecords: 2
      )
    }
    task.cancel()
    gate.continuation.yield(())
    gate.continuation.finish()

    do {
      _ = try await task.value
      failTest("Expected a cancelled validation task to stop before parsing")
    } catch is CancellationError {
      // Expected: parsing observes the detached validation task's cancellation state.
    }
  }

  @Test
  func testRejectsInvalidSummaryBeforeTrustingArtifacts() throws {
    let root = try makeOutput(summary: TestFixtures.summary())
    let invalid = TestFixtures.summary(
      extraction: TestFixtures.extraction(filesExpected: 7, filesExtracted: 6)
    )
    assertValidationError(.invalidSummary) {
      try RecoveryOutputValidator.validate(invalid, beneath: root)
    }
  }

  @Test
  func testRejectsUnexpectedOuterAndExtractionRootMembers() throws {
    let summary = TestFixtures.summary()

    let outerRoot = try makeOutput(summary: summary)
    try TestFixtures.writePrivate(
      Data("unexpected".utf8),
      at: outerRoot.appendingPathComponent("unexpected.txt")
    )
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: outerRoot)
    }

    let extractionRoot = try makeOutput(summary: summary)
    try TestFixtures.writePrivate(
      Data("unexpected".utf8),
      at: extractionRoot.appendingPathComponent(
        "\(RecoveryArtifacts.expectedExtractionDirectory)/unexpected.txt"
      )
    )
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: extractionRoot)
    }
  }

  @Test
  func testRejectsNonFileAndMissingRoot() throws {
    assertValidationError(.unsafeArtifact) {
      try RecoveryOutputValidator.validate(
        TestFixtures.summary(),
        beneath: URL(string: "https://example.invalid/output")!
      )
    }
    let missing = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    assertValidationError(.missingArtifact) {
      try RecoveryOutputValidator.validate(TestFixtures.summary(), beneath: missing)
    }
  }

  @Test
  func testRejectsMissingRequiredReportAndPDF() throws {
    let summary = TestFixtures.summary()
    let missingReport = try makeOutput(summary: summary)
    try FileManager.default.removeItem(
      at: missingReport.appendingPathComponent(RecoveryArtifacts.expectedReport)
    )
    assertValidationError(.missingArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: missingReport)
    }

    let missingPDF = try makeOutput(summary: summary)
    try FileManager.default.removeItem(
      at: missingPDF.appendingPathComponent(RecoveryArtifacts.expectedPDFReport)
    )
    assertValidationError(.missingArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: missingPDF)
    }
  }

  @Test
  func testRejectsWrongArtifactTypesAndSymlinksWithoutFollowing() throws {
    let summary = TestFixtures.summary()
    let wrongType = try makeOutput(summary: summary)
    let report = wrongType.appendingPathComponent(RecoveryArtifacts.expectedReport)
    try FileManager.default.removeItem(at: report)
    try FileManager.default.createDirectory(at: report, withIntermediateDirectories: false)
    try TestFixtures.setMode(0o700, at: report)
    assertValidationError(.unsafeArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: wrongType)
    }

    let symlinkRoot = try makeOutput(summary: summary)
    let visual = symlinkRoot.appendingPathComponent(RecoveryArtifacts.expectedVisualReport)
    let external = try trackedDirectory()
    let externalFile = external.appendingPathComponent("outside.html")
    try TestFixtures.writePrivate(Data("outside".utf8), at: externalFile)
    try FileManager.default.removeItem(at: visual)
    try FileManager.default.createSymbolicLink(at: visual, withDestinationURL: externalFile)
    assertValidationError(.unsafeArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: symlinkRoot)
    }
  }

  @Test
  func testRejectsSymlinkedIntermediateDirectoryAndRoot() throws {
    let summary = TestFixtures.summary()
    let parent = try trackedDirectory()
    let realRoot = parent.appendingPathComponent("real", isDirectory: true)
    try TestFixtures.makePrivateOutput(at: realRoot, summary: summary)
    let linkedRoot = parent.appendingPathComponent("linked", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: linkedRoot, withDestinationURL: realRoot)
    assertValidationError(.unsafeArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: linkedRoot)
    }

    let intermediateRoot = try makeOutput(summary: summary)
    let extraction = intermediateRoot.appendingPathComponent(
      RecoveryArtifacts.expectedExtractionDirectory
    )
    let externalExtraction = parent.appendingPathComponent("external-extraction")
    try FileManager.default.moveItem(at: extraction, to: externalExtraction)
    try FileManager.default.createSymbolicLink(
      at: extraction,
      withDestinationURL: externalExtraction
    )
    assertValidationError(.unsafeArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: intermediateRoot)
    }
  }

  @Test
  func testRejectsSymlinkedAncestorBeforeOpeningOutputRoot() throws {
    let summary = TestFixtures.summary()
    let container = try trackedDirectory()
    let realParent = container.appendingPathComponent("real-parent", isDirectory: true)
    let realRoot = realParent.appendingPathComponent("output", isDirectory: true)
    try TestFixtures.makePrivateOutput(at: realRoot, summary: summary)

    let linkedParent = container.appendingPathComponent("linked-parent", isDirectory: true)
    try FileManager.default.createSymbolicLink(
      at: linkedParent,
      withDestinationURL: realParent
    )
    let rootThroughLinkedAncestor = linkedParent.appendingPathComponent(
      "output",
      isDirectory: true
    )

    assertValidationError(.unsafeArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: rootThroughLinkedAncestor)
    }
  }

  @Test
  func testRejectsGroupOrWorldAccessibleRootDirectoryAndFile() throws {
    let summary = TestFixtures.summary()
    let publicRoot = try makeOutput(summary: summary)
    try TestFixtures.setMode(0o750, at: publicRoot)
    assertValidationError(.insecurePermissions) {
      try RecoveryOutputValidator.validate(summary, beneath: publicRoot)
    }

    let publicFileRoot = try makeOutput(summary: summary)
    try TestFixtures.setMode(
      0o640,
      at: publicFileRoot.appendingPathComponent(RecoveryArtifacts.expectedReport)
    )
    assertValidationError(.insecurePermissions) {
      try RecoveryOutputValidator.validate(summary, beneath: publicFileRoot)
    }
  }

  @Test
  func testRejectsExtendedACLOnPrivateFileAndDirectoryDespitePrivateModes() throws {
    let summary = TestFixtures.summary()
    let fileRoot = try makeOutput(summary: summary)
    let report = fileRoot.appendingPathComponent(RecoveryArtifacts.expectedReport)
    try addACL("everyone allow read", to: report)
    assertValidationError(.insecurePermissions) {
      try RecoveryOutputValidator.validate(summary, beneath: fileRoot)
    }

    let directoryRoot = try makeOutput(summary: summary)
    let manifest = directoryRoot.appendingPathComponent(
      "TVTime-Extraction/manifest",
      isDirectory: true
    )
    try addACL("everyone allow list", to: manifest)
    assertValidationError(.insecurePermissions) {
      try RecoveryOutputValidator.validate(summary, beneath: directoryRoot)
    }
  }

  @Test
  func testRejectsRetainedOrInjectedManifestEntry() throws {
    let summary = TestFixtures.summary()
    let root = try makeOutput(summary: summary)
    let retainedManifest = root.appendingPathComponent(
      "TVTime-Extraction/manifest/Manifest.decrypted.db"
    )
    try TestFixtures.writePrivate(Data("synthetic manifest".utf8), at: retainedManifest)
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: root)
    }
  }

  @Test
  func testRejectsMissingEmptyOversizedAndSymlinkedCompletionMarkers() throws {
    let summary = TestFixtures.summary()
    let missing = try makeOutput(summary: summary)
    let missingMarker = missing.appendingPathComponent(RecoveryArtifacts.expectedRecoveryState)
    try FileManager.default.removeItem(at: missingMarker)
    assertValidationError(.missingArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: missing)
    }

    let empty = try makeOutput(summary: summary)
    let emptyMarker = empty.appendingPathComponent(RecoveryArtifacts.expectedRecoveryState)
    try TestFixtures.writePrivate(Data(), at: emptyMarker)
    assertValidationError(.unreadableCompletionMarker) {
      try RecoveryOutputValidator.validate(summary, beneath: empty)
    }

    let oversized = try makeOutput(summary: summary)
    let oversizedMarker = oversized.appendingPathComponent(
      RecoveryArtifacts.expectedRecoveryState
    )
    try TestFixtures.writePrivate(Data(repeating: 0x61, count: 64 * 1_024 + 1), at: oversizedMarker)
    assertValidationError(.unreadableCompletionMarker) {
      try RecoveryOutputValidator.validate(summary, beneath: oversized)
    }

    let symlinked = try makeOutput(summary: summary)
    let marker = symlinked.appendingPathComponent(RecoveryArtifacts.expectedRecoveryState)
    let external = try trackedDirectory().appendingPathComponent("state.json")
    try TestFixtures.writePrivate(Data("{}".utf8), at: external)
    try FileManager.default.removeItem(at: marker)
    try FileManager.default.createSymbolicLink(at: marker, withDestinationURL: external)
    assertValidationError(.unsafeArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: symlinked)
    }
  }

  @Test
  func testRejectsMalformedIncompleteAndPDFMismatchedCompletionMarkers() throws {
    let summary = TestFixtures.summary()
    let malformed = try makeOutput(summary: summary)
    try TestFixtures.writePrivate(
      Data("not-json".utf8),
      at: malformed.appendingPathComponent(RecoveryArtifacts.expectedRecoveryState)
    )
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: malformed)
    }

    let incomplete = try makeOutput(summary: summary, markerOverrides: ["status": "running"])
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: incomplete)
    }

    let missingReportFlag = try makeOutput(summary: summary)
    try TestFixtures.rewriteRecoveryMarker(beneath: missingReportFlag) { marker in
      var bindings = try #require(marker["artifacts"] as? [[String: Any]])
      bindings.removeAll { $0["id"] as? String == "html_report" }
      marker["artifacts"] = bindings
    }
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: missingReportFlag)
    }

    let mismatchedPDF = try makeOutput(summary: summary)
    try TestFixtures.rewriteRecoveryMarker(beneath: mismatchedPDF) { marker in
      marker["pdf"] = ["status": "omitted", "artifact_id": NSNull()]
    }
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: mismatchedPDF)
    }
  }

  @Test
  func testRejectsUnknownKeysThroughoutCompletionMarkerSchema() throws {
    typealias MarkerMutation = (inout [String: Any]) throws -> Void
    let mutations: [(String, MarkerMutation)] = [
      ("top level", { marker in marker["unexpected"] = true }),
      (
        "PDF state",
        { marker in
          var pdf = try #require(marker["pdf"] as? [String: Any])
          pdf["unexpected"] = true
          marker["pdf"] = pdf
        }
      ),
      (
        "source snapshot",
        { marker in
          var source = try #require(marker["source_snapshot"] as? [String: Any])
          source["unexpected"] = true
          marker["source_snapshot"] = source
        }
      ),
      (
        "inventory identity",
        { marker in
          var source = try #require(marker["source_snapshot"] as? [String: Any])
          var inventory = try #require(source["inventory"] as? [String: Any])
          inventory["unexpected"] = true
          source["inventory"] = inventory
          marker["source_snapshot"] = source
        }
      ),
      (
        "raw-tree identity",
        { marker in
          var source = try #require(marker["source_snapshot"] as? [String: Any])
          var rawTree = try #require(source["raw_tree"] as? [String: Any])
          rawTree["unexpected"] = true
          source["raw_tree"] = rawTree
          marker["source_snapshot"] = source
        }
      ),
      (
        "aggregates",
        { marker in
          var aggregates = try #require(marker["aggregates"] as? [String: Any])
          aggregates["unexpected"] = true
          marker["aggregates"] = aggregates
        }
      ),
      (
        "extraction aggregate",
        { marker in
          var aggregates = try #require(marker["aggregates"] as? [String: Any])
          var extraction = try #require(aggregates["extraction"] as? [String: Any])
          extraction["unexpected"] = true
          aggregates["extraction"] = extraction
          marker["aggregates"] = aggregates
        }
      ),
      (
        "analysis aggregate",
        { marker in
          var aggregates = try #require(marker["aggregates"] as? [String: Any])
          var analysis = try #require(aggregates["analysis"] as? [String: Any])
          analysis["unexpected"] = true
          aggregates["analysis"] = analysis
          marker["aggregates"] = aggregates
        }
      ),
      (
        "report aggregate",
        { marker in
          var aggregates = try #require(marker["aggregates"] as? [String: Any])
          var report = try #require(aggregates["report"] as? [String: Any])
          report["unexpected"] = true
          aggregates["report"] = report
          marker["aggregates"] = aggregates
        }
      ),
      (
        "artifact binding",
        { marker in
          var artifacts = try #require(marker["artifacts"] as? [[String: Any]])
          artifacts[0]["unexpected"] = true
          marker["artifacts"] = artifacts
        }
      ),
    ]

    for (label, mutation) in mutations {
      let root = try makeOutput(summary: TestFixtures.summary())
      try TestFixtures.rewriteRecoveryMarker(beneath: root, transform: mutation)
      expectThrowsError(
        try RecoveryOutputValidator.validate(TestFixtures.summary(), beneath: root),
        "Expected unknown key in \(label) to fail closed"
      ) { error in
        guard case RecoveryOutputValidationError.incompleteOutput = error else {
          return failTest("Unexpected error for \(label): \(error)")
        }
      }
    }
  }

  @Test
  func testRejectsDuplicateKeysAcrossEveryCompletionContract() throws {
    let summary = TestFixtures.summary()

    let recoveryRoot = try makeOutput(summary: summary)
    let recoveryState = recoveryRoot.appendingPathComponent(
      RecoveryArtifacts.expectedRecoveryState
    )
    try duplicateStatusKey(in: recoveryState, usingEscapedEquivalent: true)
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: recoveryRoot)
    }

    let runRoot = try makeOutput(summary: summary)
    let runState = runRoot.appendingPathComponent(
      "TVTime-Extraction/metadata/run_state.json"
    )
    try duplicateStatusKey(in: runState, usingEscapedEquivalent: false)
    try TestFixtures.refreshArtifactBinding(beneath: runRoot, id: "extraction_run_state")
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: runRoot)
    }

    let extractionSummaryRoot = try makeOutput(summary: summary)
    let extractionSummary = extractionSummaryRoot.appendingPathComponent(
      "TVTime-Extraction/metadata/summary.json"
    )
    try duplicateBundleIDKey(in: extractionSummary)
    try TestFixtures.refreshArtifactBinding(
      beneath: extractionSummaryRoot,
      id: "extraction_summary"
    )
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: extractionSummaryRoot)
    }

    let analysisRoot = try makeOutput(summary: summary)
    let analysisSummary = analysisRoot.appendingPathComponent(
      "TVTime-Extraction/analysis/analysis_summary.json"
    )
    try duplicateStatusKey(in: analysisSummary, usingEscapedEquivalent: true)
    try TestFixtures.refreshArtifactBinding(beneath: analysisRoot, id: "analysis_summary")
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: analysisRoot)
    }
  }

  @Test
  func testRejectsUnknownKeysInRunAndAnalysisSummarySchemas() throws {
    typealias JSONMutation = (inout [String: Any]) throws -> Void
    let runMutations: [(String, JSONMutation)] = [
      ("run-state root", { state in state["unexpected"] = true }),
      (
        "run-state source snapshot",
        { state in
          var source = try #require(state["source_snapshot"] as? [String: Any])
          source["unexpected"] = true
          state["source_snapshot"] = source
        }
      ),
    ]
    for (label, mutation) in runMutations {
      let root = try makeOutput(summary: TestFixtures.summary())
      try rewriteBoundJSON(
        beneath: root,
        relativePath: "TVTime-Extraction/metadata/run_state.json",
        artifactID: "extraction_run_state",
        transform: mutation
      )
      expectThrowsError(
        try RecoveryOutputValidator.validate(TestFixtures.summary(), beneath: root),
        "Expected unknown key in \(label) to fail closed"
      ) { error in
        guard case RecoveryOutputValidationError.incompleteOutput = error else {
          return failTest("Unexpected error for \(label): \(error)")
        }
      }
    }

    let extractionSummaryRoot = try makeOutput(summary: TestFixtures.summary())
    try rewriteBoundJSON(
      beneath: extractionSummaryRoot,
      relativePath: "TVTime-Extraction/metadata/summary.json",
      artifactID: "extraction_summary"
    ) { state in
      state["unexpected"] = true
    }
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(
        TestFixtures.summary(),
        beneath: extractionSummaryRoot
      )
    }

    let analysisMutations: [(String, JSONMutation)] = [
      ("analysis-summary root", { state in state["unexpected"] = true }),
      (
        "analysis CSV escape coordinate",
        { state in
          state["csv_spreadsheet_escaped_cells"] = [
            "synthetic.csv": [["row": 1, "field": "name", "unexpected": true]]
          ]
        }
      ),
    ]
    for (label, mutation) in analysisMutations {
      let root = try makeOutput(summary: TestFixtures.summary())
      try rewriteBoundJSON(
        beneath: root,
        relativePath: "TVTime-Extraction/analysis/analysis_summary.json",
        artifactID: "analysis_summary",
        transform: mutation
      )
      expectThrowsError(
        try RecoveryOutputValidator.validate(TestFixtures.summary(), beneath: root),
        "Expected unknown key in \(label) to fail closed"
      ) { error in
        guard case RecoveryOutputValidationError.incompleteOutput = error else {
          return failTest("Unexpected error for \(label): \(error)")
        }
      }
    }
  }

  @Test
  func testStrictJSONValidationIsDepthAndNodeBounded() throws {
    let duplicate = Data(#"{"status":1,"statu\u0073":2}"#.utf8)
    expectThrowsError(
      try StrictJSONValidator.validate(duplicate, maximumBytes: 64 * 1_024)
    )

    let canonicallyEquivalentButDistinct = Data(#"{"\u00e9":1,"e\u0301":2}"#.utf8)
    expectNoThrow(
      try StrictJSONValidator.validate(
        canonicallyEquivalentButDistinct,
        maximumBytes: 64 * 1_024
      )
    )

    let depth = StrictJSONValidator.maximumDepth + 2
    let tooDeep = Data(
      (String(repeating: "[", count: depth) + "0" + String(repeating: "]", count: depth)).utf8
    )
    expectThrowsError(
      try StrictJSONValidator.validate(tooDeep, maximumBytes: 64 * 1_024)
    )
  }

  @Test
  func testRejectsInvalidUTF8InsideStrictlyValidatedJSONValue() throws {
    let summary = TestFixtures.summary()
    let root = try makeOutput(summary: summary)
    let analysisSummary = root.appendingPathComponent(
      "TVTime-Extraction/analysis/analysis_summary.json"
    )
    var data = try Data(contentsOf: analysisSummary)
    let field = Data(#""dio_cache_quick_check":"ok""#.utf8)
    let fieldRange = try #require(data.range(of: field))
    let valueRange = try #require(
      data.range(of: Data(#""ok""#.utf8), in: fieldRange)
    )
    data[valueRange.lowerBound + 1] = 0xFF
    try TestFixtures.writePrivate(data, at: analysisSummary)
    try TestFixtures.refreshArtifactBinding(beneath: root, id: "analysis_summary")

    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: root)
    }
  }

  @Test
  func testRejectsMissingAndIncompleteExtractionRunState() throws {
    let summary = TestFixtures.summary()
    let missing = try makeOutput(summary: summary)
    try FileManager.default.removeItem(
      at: missing.appendingPathComponent("TVTime-Extraction/metadata/run_state.json")
    )
    assertValidationError(.missingArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: missing)
    }

    let incomplete = try makeOutput(summary: summary)
    let runState = incomplete.appendingPathComponent(
      "TVTime-Extraction/metadata/run_state.json"
    )
    try TestFixtures.writePrivate(
      Data(
        "{\"schema_version\":2,\"contract\":\"tvtime-extraction-run-state-v0.2\",\"status\":\"incomplete\",\"files_expected\":7,\"files_extracted\":7,\"bytes_extracted\":12345,\"selected_declared_bytes\":12345,\"size_discrepancy_count\":0}"
          .utf8
      ),
      at: runState
    )
    try TestFixtures.refreshArtifactBinding(beneath: incomplete, id: "extraction_run_state")
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: incomplete)
    }

    let oversized = try makeOutput(summary: summary)
    let oversizedRunState = oversized.appendingPathComponent(
      "TVTime-Extraction/metadata/run_state.json"
    )
    try TestFixtures.writePrivate(
      Data(repeating: 0x61, count: 64 * 1024 + 1), at: oversizedRunState)
    try TestFixtures.refreshArtifactBinding(beneath: oversized, id: "extraction_run_state")
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: oversized)
    }
  }

  @Test
  func testRejectsZeroTruncatedSwappedAndFormatCorruptedReports() throws {
    let summary = TestFixtures.summary()
    let zero = try makeOutput(summary: summary)
    try TestFixtures.writePrivate(
      Data(),
      at: zero.appendingPathComponent(RecoveryArtifacts.expectedReport)
    )
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: zero)
    }

    let truncated = try makeOutput(summary: summary)
    let truncatedReport = truncated.appendingPathComponent(RecoveryArtifacts.expectedReport)
    let original = try Data(contentsOf: truncatedReport)
    try TestFixtures.writePrivate(Data(original.prefix(original.count / 2)), at: truncatedReport)
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: truncated)
    }

    let swapped = try makeOutput(summary: summary)
    let swappedReport = swapped.appendingPathComponent(RecoveryArtifacts.expectedReport)
    let swappedOriginal = try Data(contentsOf: swappedReport)
    try TestFixtures.writePrivate(
      Data(repeating: 0x58, count: swappedOriginal.count),
      at: swappedReport
    )
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: swapped)
    }

    let wrongFormat = try makeOutput(summary: summary)
    let wrongFormatReport = wrongFormat.appendingPathComponent(RecoveryArtifacts.expectedReport)
    let wrongFormatOriginal = try Data(contentsOf: wrongFormatReport)
    var wrongFormatData = Data("not markdown".utf8)
    wrongFormatData.append(
      Data(repeating: 0x20, count: wrongFormatOriginal.count - wrongFormatData.count))
    try TestFixtures.writePrivate(wrongFormatData, at: wrongFormatReport)
    try TestFixtures.refreshArtifactBinding(beneath: wrongFormat, id: "markdown_report")
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: wrongFormat)
    }
  }

  @Test
  func testRejectsMarkerHashSizeCountPDFAndArtifactSetMismatches() throws {
    let summary = TestFixtures.summary()
    let badHash = try makeOutput(summary: summary)
    try TestFixtures.rewriteRecoveryMarker(beneath: badHash) { marker in
      var bindings = try #require(marker["artifacts"] as? [[String: Any]])
      let index = try #require(bindings.firstIndex { $0["id"] as? String == "markdown_report" })
      bindings[index]["sha256"] = String(repeating: "0", count: 64)
      marker["artifacts"] = bindings
    }
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: badHash)
    }

    let badSize = try makeOutput(summary: summary)
    try TestFixtures.rewriteRecoveryMarker(beneath: badSize) { marker in
      var bindings = try #require(marker["artifacts"] as? [[String: Any]])
      let index = try #require(bindings.firstIndex { $0["id"] as? String == "html_report" })
      bindings[index]["bytes"] = 1
      marker["artifacts"] = bindings
    }
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: badSize)
    }

    let badCount = try makeOutput(summary: summary)
    try TestFixtures.rewriteRecoveryMarker(beneath: badCount) { marker in
      var aggregates = try #require(marker["aggregates"] as? [String: Any])
      var analysis = try #require(aggregates["analysis"] as? [String: Any])
      analysis["series_library"] = summary.analysis.seriesLibrary + 1
      aggregates["analysis"] = analysis
      marker["aggregates"] = aggregates
    }
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: badCount)
    }

    let badPDF = try makeOutput(summary: summary)
    try TestFixtures.rewriteRecoveryMarker(beneath: badPDF) { marker in
      var pdf = try #require(marker["pdf"] as? [String: Any])
      pdf["artifact_id"] = NSNull()
      marker["pdf"] = pdf
    }
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: badPDF)
    }

    let extraArtifact = try makeOutput(summary: summary)
    try TestFixtures.rewriteRecoveryMarker(beneath: extraArtifact) { marker in
      var bindings = try #require(marker["artifacts"] as? [[String: Any]])
      bindings.append(bindings[0])
      marker["artifacts"] = bindings
    }
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: extraArtifact)
    }
  }

  @Test
  func testRejectsRemovedChangedAndExtraRawFilesAfterCompletionSeal() throws {
    let summary = TestFixtures.summary()

    let removed = try makeOutput(summary: summary)
    try FileManager.default.removeItem(at: firstSyntheticRawFile(beneath: removed))
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: removed)
    }

    let changed = try makeOutput(summary: summary)
    let changedFile = firstSyntheticRawFile(beneath: changed)
    let original = try Data(contentsOf: changedFile)
    try TestFixtures.writePrivate(
      Data(repeating: 0xA5, count: original.count),
      at: changedFile
    )
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: changed)
    }

    let extra = try makeOutput(summary: summary)
    let extraFile = firstSyntheticRawFile(beneath: extra)
      .deletingLastPathComponent()
      .appendingPathComponent("Unexpected.bin")
    try TestFixtures.writePrivate(Data("unexpected".utf8), at: extraFile)
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: extra)
    }

    let extraDirectory = try makeOutput(summary: summary)
    let unexpectedDirectory = firstSyntheticRawFile(beneath: extraDirectory)
      .deletingLastPathComponent()
      .appendingPathComponent("UnexpectedEmptyDirectory", isDirectory: true)
    try FileManager.default.createDirectory(
      at: unexpectedDirectory,
      withIntermediateDirectories: false
    )
    try TestFixtures.setMode(0o700, at: unexpectedDirectory)
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: extraDirectory)
    }
  }

  @Test
  func testRejectsExtraFilesAndSubdirectoriesInSealedMetadataAndAnalysis() throws {
    let summary = TestFixtures.summary()
    for directory in ["metadata", "analysis"] {
      let extraFileRoot = try makeOutput(summary: summary)
      let extraFile = extraFileRoot.appendingPathComponent(
        "TVTime-Extraction/\(directory)/Renamed-Sensitive-Export.bin"
      )
      try TestFixtures.writePrivate(Data("synthetic private export".utf8), at: extraFile)
      assertValidationError(.incompleteOutput) {
        try RecoveryOutputValidator.validate(summary, beneath: extraFileRoot)
      }

      let extraDirectoryRoot = try makeOutput(summary: summary)
      let extraDirectory = extraDirectoryRoot.appendingPathComponent(
        "TVTime-Extraction/\(directory)/Renamed-Sensitive-Export",
        isDirectory: true
      )
      try FileManager.default.createDirectory(
        at: extraDirectory,
        withIntermediateDirectories: false
      )
      try TestFixtures.setMode(0o700, at: extraDirectory)
      assertValidationError(.incompleteOutput) {
        try RecoveryOutputValidator.validate(summary, beneath: extraDirectoryRoot)
      }
    }
  }

  @Test
  func testRejectsExtraSymlinksInSealedMetadataAndAnalysis() throws {
    let summary = TestFixtures.summary()
    for directory in ["metadata", "analysis"] {
      let root = try makeOutput(summary: summary)
      let external = try trackedDirectory().appendingPathComponent("private-export.bin")
      try TestFixtures.writePrivate(Data("synthetic private export".utf8), at: external)
      let link = root.appendingPathComponent(
        "TVTime-Extraction/\(directory)/Renamed-Sensitive-Export"
      )
      try FileManager.default.createSymbolicLink(at: link, withDestinationURL: external)
      assertValidationError(.incompleteOutput) {
        try RecoveryOutputValidator.validate(summary, beneath: root)
      }
    }
  }

  @Test
  func testExactMembershipRequiresDomainsAndAppliesConditionalPDFRule() throws {
    let summary = TestFixtures.summary()
    let missingDomains = try makeOutput(summary: summary)
    try FileManager.default.removeItem(
      at: missingDomains.appendingPathComponent("TVTime-Extraction/metadata/domains.txt")
    )
    assertValidationError(.missingArtifact) {
      try RecoveryOutputValidator.validate(summary, beneath: missingDomains)
    }

    let tamperedDomains = try makeOutput(summary: summary)
    try TestFixtures.writePrivate(
      Data("AppDomain-com.tozelabs.tvshowtime-tampered\n".utf8),
      at: tamperedDomains.appendingPathComponent("TVTime-Extraction/metadata/domains.txt")
    )
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: tamperedDomains)
    }

    let omittedSummary = TestFixtures.omittedPDFSummary()
    let unexpectedPDF = try makeOutput(summary: omittedSummary)
    try TestFixtures.writePrivate(
      Data("%PDF-1.4\nsynthetic".utf8),
      at: unexpectedPDF.appendingPathComponent(RecoveryArtifacts.expectedPDFReport)
    )
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(omittedSummary, beneath: unexpectedPDF)
    }
  }

  @Test
  func testRejectsCompletionMarkerMutationDuringValidation() throws {
    let summary = TestFixtures.summary()
    let root = try makeOutput(summary: summary)
    let marker = root.appendingPathComponent(RecoveryArtifacts.expectedRecoveryState)
    var mutatedMarker = try Data(contentsOf: marker)
    mutatedMarker.append(0x0A)

    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(
        summary,
        beneath: root,
        beforeFinalCompletionMarkerRead: {
          try TestFixtures.writePrivate(mutatedMarker, at: marker)
        }
      )
    }
  }

  @Test
  func testRejectsPostSealInventoryMutationAndRunRecoverySnapshotMismatch() throws {
    let summary = TestFixtures.summary()
    let inventoryChanged = try makeOutput(summary: summary)
    let inventory = inventoryChanged.appendingPathComponent(
      "TVTime-Extraction/metadata/inventory.csv"
    )
    var payload = try Data(contentsOf: inventory)
    payload.append(Data("\r\n".utf8))
    try TestFixtures.writePrivate(payload, at: inventory)
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: inventoryChanged)
    }

    let mismatched = try makeOutput(summary: summary)
    let runState = mismatched.appendingPathComponent(
      "TVTime-Extraction/metadata/run_state.json"
    )
    let decoded = try JSONSerialization.jsonObject(with: Data(contentsOf: runState))
    var state = try #require(decoded as? [String: Any])
    var source = try #require(state["source_snapshot"] as? [String: Any])
    var rawTree = try #require(source["raw_tree"] as? [String: Any])
    rawTree["sha256"] = String(repeating: "0", count: 64)
    source["raw_tree"] = rawTree
    state["source_snapshot"] = source
    try TestFixtures.writePrivate(
      JSONSerialization.data(withJSONObject: state, options: [.sortedKeys]),
      at: runState
    )
    try TestFixtures.refreshArtifactBinding(beneath: mismatched, id: "extraction_run_state")
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: mismatched)
    }
  }

  @Test
  func testRequiresExactSizeDiscrepanciesDerivedFromInventory() throws {
    let extraction = TestFixtures.extraction(
      selectedDeclaredBytes: 12_346,
      sizeDiscrepancyCount: 1
    )
    let summary = TestFixtures.summary(extraction: extraction)
    let root = try makeOutput(summary: summary)
    let inventoryURL = root.appendingPathComponent(
      "TVTime-Extraction/metadata/inventory.csv"
    )
    let inventoryText = try #require(
      String(data: Data(contentsOf: inventoryURL), encoding: .utf8)
    )
    var lines = inventoryText.components(separatedBy: "\r\n")
    var fields = lines[1].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
    let actualSize = try #require(Int64(fields[4]))
    fields[3] = String(actualSize + 1)
    fields[5] = "False"
    lines[1] = fields.joined(separator: ",")
    let inventoryData = Data(lines.joined(separator: "\r\n").utf8)
    try TestFixtures.writePrivate(inventoryData, at: inventoryURL)
    let inventoryIdentity: [String: Any] = [
      "bytes": inventoryData.count,
      "sha256": SHA256.hash(data: inventoryData).map { String(format: "%02x", $0) }
        .joined(),
    ]
    let discrepancy: [String: Any] = [
      "domain": fields[1],
      "relative_path": fields[2],
      "declared_size": actualSize + 1,
      "actual_size": actualSize,
    ]

    try rewriteBoundJSON(
      beneath: root,
      relativePath: "TVTime-Extraction/metadata/summary.json",
      artifactID: "extraction_summary"
    ) { state in
      state["size_discrepancies"] = [discrepancy]
    }
    try rewriteBoundJSON(
      beneath: root,
      relativePath: "TVTime-Extraction/metadata/run_state.json",
      artifactID: "extraction_run_state"
    ) { state in
      var source = try #require(state["source_snapshot"] as? [String: Any])
      source["inventory"] = inventoryIdentity
      state["source_snapshot"] = source
    }
    try TestFixtures.rewriteRecoveryMarker(beneath: root) { marker in
      var source = try #require(marker["source_snapshot"] as? [String: Any])
      source["inventory"] = inventoryIdentity
      marker["source_snapshot"] = source
    }
    try TestFixtures.refreshArtifactBinding(beneath: root, id: "extraction_inventory")

    expectNoThrow(try RecoveryOutputValidator.validate(summary, beneath: root))

    try rewriteBoundJSON(
      beneath: root,
      relativePath: "TVTime-Extraction/metadata/summary.json",
      artifactID: "extraction_summary"
    ) { state in
      var mismatched = discrepancy
      mismatched["relative_path"] = "Documents/Synthetic-0002.bin"
      state["size_discrepancies"] = [mismatched]
    }
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: root)
    }
  }

  @Test
  func testRejectsStaleSelectedDeclaredByteTotalAfterBoundInventoryMutation() throws {
    let extraction = TestFixtures.extraction(
      selectedDeclaredBytes: 12_346,
      sizeDiscrepancyCount: 1
    )
    let summary = TestFixtures.summary(extraction: extraction)
    let root = try makeOutput(summary: summary)
    let inventoryURL = root.appendingPathComponent(
      "TVTime-Extraction/metadata/inventory.csv"
    )
    let inventoryText = try #require(
      String(data: Data(contentsOf: inventoryURL), encoding: .utf8)
    )
    var lines = inventoryText.components(separatedBy: "\r\n")
    var fields = lines[1].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
    let actualSize = try #require(Int64(fields[4]))
    fields[3] = String(actualSize + 2)
    fields[5] = "False"
    lines[1] = fields.joined(separator: ",")
    try rebindInventory(Data(lines.joined(separator: "\r\n").utf8), beneath: root)

    try rewriteBoundJSON(
      beneath: root,
      relativePath: "TVTime-Extraction/metadata/summary.json",
      artifactID: "extraction_summary"
    ) { state in
      state["size_discrepancies"] = [
        [
          "domain": fields[1],
          "relative_path": fields[2],
          "declared_size": actualSize + 2,
          "actual_size": actualSize,
        ]
      ]
    }

    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: root)
    }
  }

  @Test
  func testRejectsOverflowWhileSummingInventoryDeclaredBytes() throws {
    let extraction = TestFixtures.extraction(
      selectedDeclaredBytes: Int64.max,
      sizeDiscrepancyCount: 2
    )
    let summary = TestFixtures.summary(extraction: extraction)
    let root = try makeOutput(summary: summary)
    let inventoryURL = root.appendingPathComponent(
      "TVTime-Extraction/metadata/inventory.csv"
    )
    let inventoryText = try #require(
      String(data: Data(contentsOf: inventoryURL), encoding: .utf8)
    )
    var lines = inventoryText.components(separatedBy: "\r\n")
    var first = lines[1].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
    var second = lines[2].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
    let firstActualSize = try #require(Int64(first[4]))
    let secondActualSize = try #require(Int64(second[4]))
    first[3] = String(Int64.max)
    first[5] = "False"
    second[3] = "1"
    second[5] = "False"
    lines[1] = first.joined(separator: ",")
    lines[2] = second.joined(separator: ",")
    try rebindInventory(Data(lines.joined(separator: "\r\n").utf8), beneath: root)

    try rewriteBoundJSON(
      beneath: root,
      relativePath: "TVTime-Extraction/metadata/summary.json",
      artifactID: "extraction_summary"
    ) { state in
      state["size_discrepancies"] = [
        [
          "domain": first[1],
          "relative_path": first[2],
          "declared_size": Int64.max,
          "actual_size": firstActualSize,
        ],
        [
          "domain": second[1],
          "relative_path": second[2],
          "declared_size": 1,
          "actual_size": secondActualSize,
        ],
      ]
    }

    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: root)
    }
  }

  @Test
  func testRejectsCorruptionOfDeterministicNonHumanAnalysisTable() throws {
    let summary = TestFixtures.summary()
    let root = try makeOutput(summary: summary)
    let cacheIndex = root.appendingPathComponent(
      "TVTime-Extraction/analysis/cache_index.csv"
    )
    let original = try Data(contentsOf: cacheIndex)
    try TestFixtures.writePrivate(
      Data(repeating: 0x58, count: original.count),
      at: cacheIndex
    )
    assertValidationError(.artifactIntegrityFailure) {
      try RecoveryOutputValidator.validate(summary, beneath: root)
    }
  }

  @Test
  func testRejectsOptionalOrInjectedRawCacheResponseExports() throws {
    let summary = TestFixtures.summary()
    let injected = try makeOutput(summary: summary)
    let responses = injected.appendingPathComponent(
      "TVTime-Extraction/analysis/cache_responses",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: responses, withIntermediateDirectories: false)
    try TestFixtures.setMode(0o700, at: responses)
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: injected)
    }

    let enabled = try makeOutput(summary: summary)
    let analysisSummary = enabled.appendingPathComponent(
      "TVTime-Extraction/analysis/analysis_summary.json"
    )
    let decoded = try JSONSerialization.jsonObject(with: Data(contentsOf: analysisSummary))
    var state = try #require(decoded as? [String: Any])
    state["raw_cache_exported"] = true
    try TestFixtures.writePrivate(
      JSONSerialization.data(withJSONObject: state, options: [.sortedKeys]),
      at: analysisSummary
    )
    try TestFixtures.refreshArtifactBinding(beneath: enabled, id: "analysis_summary")
    assertValidationError(.incompleteOutput) {
      try RecoveryOutputValidator.validate(summary, beneath: enabled)
    }
  }

  private func makeOutput(
    summary: RecoverySummary,
    markerOverrides: [String: Any] = [:]
  ) throws -> URL {
    let root = try trackedDirectory()
    try TestFixtures.makePrivateOutput(
      at: root,
      summary: summary,
      markerOverrides: markerOverrides
    )
    return root
  }

  private func duplicateStatusKey(
    in url: URL,
    usingEscapedEquivalent: Bool
  ) throws {
    let data = try Data(contentsOf: url)
    let source = try #require(String(data: data, encoding: .utf8))
    let target = #""status":"complete""#
    let replacement =
      usingEscapedEquivalent
      ? #""status":"complete","statu\u0073":"complete""#
      : #""status":"complete","status":"complete""#
    let range = try #require(source.range(of: target))
    let mutated = source.replacingCharacters(in: range, with: replacement)
    try TestFixtures.writePrivate(Data(mutated.utf8), at: url)
  }

  private func duplicateBundleIDKey(in url: URL) throws {
    let data = try Data(contentsOf: url)
    let source = try #require(String(data: data, encoding: .utf8))
    let target = #""bundle_id":"com.tozelabs.tvshowtime""#
    let replacement =
      #""bundle_id":"com.tozelabs.tvshowtime","bundle\u005fid":"com.tozelabs.tvshowtime""#
    let range = try #require(source.range(of: target))
    let mutated = source.replacingCharacters(in: range, with: replacement)
    try TestFixtures.writePrivate(Data(mutated.utf8), at: url)
  }

  private func rewriteBoundJSON(
    beneath root: URL,
    relativePath: String,
    artifactID: String,
    transform: (inout [String: Any]) throws -> Void
  ) throws {
    let url = root.appendingPathComponent(relativePath)
    let decoded = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
    var state = try #require(decoded as? [String: Any])
    try transform(&state)
    try TestFixtures.writePrivate(
      JSONSerialization.data(withJSONObject: state, options: [.sortedKeys]),
      at: url
    )
    try TestFixtures.refreshArtifactBinding(beneath: root, id: artifactID)
  }

  private func rebindInventory(_ data: Data, beneath root: URL) throws {
    let inventoryURL = root.appendingPathComponent(
      "TVTime-Extraction/metadata/inventory.csv"
    )
    try TestFixtures.writePrivate(data, at: inventoryURL)
    let identity: [String: Any] = [
      "bytes": data.count,
      "sha256": SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
    ]
    try rewriteBoundJSON(
      beneath: root,
      relativePath: "TVTime-Extraction/metadata/run_state.json",
      artifactID: "extraction_run_state"
    ) { state in
      var source = try #require(state["source_snapshot"] as? [String: Any])
      source["inventory"] = identity
      state["source_snapshot"] = source
    }
    try TestFixtures.rewriteRecoveryMarker(beneath: root) { marker in
      var source = try #require(marker["source_snapshot"] as? [String: Any])
      source["inventory"] = identity
      marker["source_snapshot"] = source
    }
    try TestFixtures.refreshArtifactBinding(beneath: root, id: "extraction_inventory")
  }

  private func trackedDirectory() throws -> URL {
    let directory = try FileManager.default.makeTestDirectory()
    temporaryDirectories.append(directory)
    return directory
  }

  private func firstSyntheticRawFile(beneath root: URL) -> URL {
    root.appendingPathComponent(
      "TVTime-Extraction/raw/AppDomain-com.tozelabs.tvshowtime/Documents/Synthetic-0001.bin"
    )
  }

  private func addACL(_ rule: String, to url: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", rule, url.path]
    try process.run()
    process.waitUntilExit()
    try #require(process.terminationStatus == 0)
  }

  private func assertValidationError(
    _ expected: RecoveryOutputValidationError,
    file: StaticString = #filePath,
    line: UInt = #line,
    operation: () throws -> Void
  ) {
    expectThrowsError(try operation(), file: file, line: line) { error in
      guard let actual = error as? RecoveryOutputValidationError else {
        return failTest("Unexpected error: \(error)", file: file, line: line)
      }
      switch (expected, actual) {
      case (.invalidSummary, .invalidSummary),
        (.missingArtifact, .missingArtifact),
        (.unsafeArtifact, .unsafeArtifact),
        (.insecurePermissions, .insecurePermissions),
        (.unreadableCompletionMarker, .unreadableCompletionMarker),
        (.incompleteOutput, .incompleteOutput),
        (.artifactIntegrityFailure, .artifactIntegrityFailure):
        break
      default:
        failTest("Expected \(expected), received \(actual)", file: file, line: line)
      }
    }
  }
}
