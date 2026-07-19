import Foundation
import Testing

@testable import TVTimeRecoveryCore

@Suite
struct RecoveryModelsTests {
  @Test
  func testNativeCompletionEnvelopeMatchesThePythonOutputContract() {
    expectEqual(RecoveryOutputContractLimits.maximumStateBytes, 64 * 1024)
    expectEqual(RecoveryOutputContractLimits.maximumSummaryBytes, 16 * 1024 * 1024)
    expectEqual(
      RecoveryOutputContractLimits.maximumGeneratedArtifactBytes,
      64 * 1024 * 1024
    )
    expectEqual(RecoveryOutputContractLimits.maximumInventoryBytes, 256 * 1024 * 1024)
    expectEqual(RecoveryOutputContractLimits.maximumInventoryRows, 100_000)
    expectEqual(RecoveryOutputContractLimits.maximumVisualRowsPerTable, 25_000)
    expectEqual(RecoveryOutputContractLimits.maximumCombinedVisualRows, 50_000)
    expectEqual(RecoveryOutputContractLimits.maximumImageReferenceRows, 25_000)
    expectEqual(RecoveryOutputContractLimits.maximumMediaReferenceOccurrences, 100_000)
  }

  @Test
  func testGeneratedAndOmittedPDFSummariesArePlausible() {
    expectTrue(TestFixtures.summary().hasPlausibleAggregateValues)
    expectTrue(TestFixtures.omittedPDFSummary().hasPlausibleAggregateValues)
  }

  @Test
  func testPreflightRequiresFinishedEncryptedBackupAndConsistentSpace() {
    expectFalse(TestFixtures.preflight(encrypted: false).hasPlausibleAggregateValues)
    expectFalse(TestFixtures.preflight(snapshotState: "in progress").hasPlausibleAggregateValues)
    expectFalse(
      TestFixtures.preflight(
        destinationFreeBytes: 100,
        minimumWorkingBytes: 200,
        hasMinimumSpace: true
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.preflight(
        destinationFreeBytes: 200,
        minimumWorkingBytes: 100,
        hasMinimumSpace: false
      ).hasPlausibleAggregateValues
    )
    expectFalse(TestFixtures.preflight(backupRegularFiles: -1).hasPlausibleAggregateValues)
  }

  @Test
  func testExtractionRequiresExactFileParityAndBoundedCounts() {
    expectFalse(
      TestFixtures.extraction(filesExpected: 7, filesExtracted: 6).hasPlausibleAggregateValues
    )
    expectFalse(TestFixtures.extraction(bytesExtracted: -1).hasPlausibleAggregateValues)
    expectFalse(
      TestFixtures.extraction(
        filesExpected: 2,
        filesExtracted: 2,
        sizeDiscrepancyCount: 3
      ).hasPlausibleAggregateValues
    )
    expectTrue(
      TestFixtures.extraction(
        filesExpected: RecoveryOutputContractLimits.maximumInventoryRows,
        filesExtracted: RecoveryOutputContractLimits.maximumInventoryRows,
        sizeDiscrepancyCount: RecoveryOutputContractLimits.maximumVisualRowsPerTable
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.extraction(
        filesExpected: RecoveryOutputContractLimits.maximumInventoryRows + 1,
        filesExtracted: RecoveryOutputContractLimits.maximumInventoryRows + 1
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.extraction(
        filesExpected: RecoveryOutputContractLimits.maximumInventoryRows,
        filesExtracted: RecoveryOutputContractLimits.maximumInventoryRows,
        sizeDiscrepancyCount: RecoveryOutputContractLimits.maximumVisualRowsPerTable + 1
      ).hasPlausibleAggregateValues
    )
  }

  @Test
  func testAnalysisRequiresRecognizedParserAndBoundedNamedEvents() {
    expectFalse(
      TestFixtures.analysis(watchEvents: 5, watchEventsWithTitles: 6).hasPlausibleAggregateValues
    )
    expectFalse(TestFixtures.analysis(favoriteShows: -1).hasPlausibleAggregateValues)
    expectFalse(TestFixtures.analysis(parserStatus: "partial").hasPlausibleAggregateValues)
    expectTrue(TestFixtures.analysis(parserStatus: "empty").hasPlausibleAggregateValues)
    expectTrue(
      TestFixtures.analysis(
        seriesLibrary: RecoveryOutputContractLimits.maximumVisualRowsPerTable,
        watchedMovies: RecoveryOutputContractLimits.maximumVisualRowsPerTable,
        movieWatchlist: 0,
        favoriteShows: 0,
        favoriteMovies: 0,
        watchEvents: 0,
        watchEventsWithTitles: 0,
        episodeCacheUnique: 0
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.analysis(
        seriesLibrary: RecoveryOutputContractLimits.maximumVisualRowsPerTable + 1,
        watchedMovies: 0,
        movieWatchlist: 0,
        favoriteShows: 0,
        favoriteMovies: 0,
        watchEvents: 0,
        watchEventsWithTitles: 0,
        episodeCacheUnique: 0
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.analysis(
        seriesLibrary: RecoveryOutputContractLimits.maximumVisualRowsPerTable,
        watchedMovies: RecoveryOutputContractLimits.maximumVisualRowsPerTable,
        movieWatchlist: 1,
        favoriteShows: 0,
        favoriteMovies: 0,
        watchEvents: 0,
        watchEventsWithTitles: 0,
        episodeCacheUnique: 0
      ).hasPlausibleAggregateValues
    )
  }

  @Test
  func testCompletedSummaryEnforcesCombinedVisualAndMediaBudgets() {
    let maximumVisualAnalysis = TestFixtures.analysis(
      seriesLibrary: RecoveryOutputContractLimits.maximumVisualRowsPerTable,
      watchedMovies: RecoveryOutputContractLimits.maximumVisualRowsPerTable,
      movieWatchlist: 0,
      favoriteShows: 0,
      favoriteMovies: 0,
      watchEvents: 0,
      watchEventsWithTitles: 0,
      episodeCacheUnique: 0
    )
    expectTrue(TestFixtures.summary(analysis: maximumVisualAnalysis).hasPlausibleAggregateValues)
    expectFalse(
      TestFixtures.summary(
        extraction: TestFixtures.extraction(sizeDiscrepancyCount: 1),
        analysis: maximumVisualAnalysis
      ).hasPlausibleAggregateValues
    )

    expectTrue(
      TestFixtures.report(
        imageCacheReferences: RecoveryOutputContractLimits.maximumImageReferenceRows,
        trailerReferences: RecoveryOutputContractLimits.maximumMediaReferenceOccurrences,
        mediaURLs: 0
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.report(
        imageCacheReferences: RecoveryOutputContractLimits.maximumImageReferenceRows + 1
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.report(
        trailerReferences: RecoveryOutputContractLimits.maximumMediaReferenceOccurrences,
        mediaURLs: 1
      ).hasPlausibleAggregateValues
    )
  }

  @Test
  func testReportRequiresPDFStatusReasonAndArtifactParity() {
    expectFalse(
      TestFixtures.summary(
        report: TestFixtures.report(pdfStatus: "generated", pdfOmissionReason: "unexpected")
      ).hasPlausibleAggregateValues
    )
    expectTrue(
      TestFixtures.summary(
        report: TestFixtures.report(pdfStatus: "omitted", pdfOmissionReason: nil),
        artifacts: TestFixtures.artifacts(pdfReport: nil)
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.summary(
        report: TestFixtures.report(pdfStatus: "omitted", pdfOmissionReason: "Unavailable")
      ).hasPlausibleAggregateValues
    )
    expectFalse(
      TestFixtures.summary(artifacts: TestFixtures.artifacts(pdfReport: nil))
        .hasPlausibleAggregateValues
    )
  }

  @Test
  func testArtifactsRequireEveryExactRelativePath() {
    let wrongPaths = [
      TestFixtures.artifacts(extractionDirectory: "../TVTime-Extraction"),
      TestFixtures.artifacts(report: "TVTime-Extraction/analysis/other.md"),
      TestFixtures.artifacts(visualReport: "/tmp/report.html"),
      TestFixtures.artifacts(analysisDirectory: "TVTime-Extraction"),
      TestFixtures.artifacts(recoveryState: "TVTime-Extraction/recovery_state.json"),
      TestFixtures.artifacts(pdfReport: "TVTime-Extraction/analysis/other.pdf"),
    ]
    for artifacts in wrongPaths {
      expectFalse(artifacts.hasExpectedRelativePaths)
    }
  }

  @Test
  func testPDFOmissionReasonIsSafeForDisplay() throws {
    let safe = TestFixtures.report(pdfStatus: "omitted", pdfOmissionReason: "Font unavailable")
    expectEqual(safe.displayPDFOmissionReason, "Font unavailable")

    let unsafe = TestFixtures.report(
      pdfStatus: "omitted",
      pdfOmissionReason: "file:///private/recovery-output"
    )
    expectNotEqual(unsafe.displayPDFOmissionReason, unsafe.pdfOmissionReason)
    let safeFallback = try requireValue(unsafe.displayPDFOmissionReason)
    expectFalse(safeFallback.localizedCaseInsensitiveContains("file:"))
  }

  @Test
  func testProgressFractionIsClampedAndHandlesUnknownTotal() {
    expectEqual(
      RecoveryProgress(stage: "x", kind: "x", message: "x", current: -1, total: 10)
        .fractionCompleted,
      0
    )
    expectEqual(
      RecoveryProgress(stage: "x", kind: "x", message: "x", current: 11, total: 10)
        .fractionCompleted,
      1
    )
    expectNil(
      RecoveryProgress(stage: "x", kind: "x", message: "x", current: 1, total: 0)
        .fractionCompleted
    )
  }

  @Test
  func testMovieAndWatchEventBreakdownsRemainExplicit() {
    let analysis = TestFixtures.analysis(
      watchedMovies: 4,
      movieWatchlist: 2,
      watchEvents: 9,
      watchEventsWithTitles: 6
    )

    expectEqual(analysis.movieCount, 6)
    expectEqual(analysis.watchedMovies, 4)
    expectEqual(analysis.movieWatchlist, 2)
    expectEqual(analysis.watchEventsWithoutTitles, 3)
  }

  @Test
  func testRecoveredRecordStateDoesNotClaimIdentifiableNames() {
    let empty = TestFixtures.analysis(
      seriesLibrary: 0,
      watchedMovies: 0,
      movieWatchlist: 0,
      favoriteShows: 0,
      favoriteMovies: 0,
      watchEvents: 0,
      watchEventsWithTitles: 0,
      episodeCacheUnique: 0
    )
    expectFalse(empty.hasRecoveredRecords)

    let placeholderOnly = TestFixtures.analysis(
      seriesLibrary: 1,
      watchedMovies: 0,
      movieWatchlist: 0,
      favoriteShows: 0,
      favoriteMovies: 0,
      watchEvents: 0,
      watchEventsWithTitles: 0,
      episodeCacheUnique: 0
    )
    expectTrue(placeholderOnly.hasRecoveredRecords)
  }
}
