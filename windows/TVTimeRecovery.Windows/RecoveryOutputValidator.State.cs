using System.Text.Json;

namespace TVTimeRecovery.Windows;

internal static partial class RecoveryOutputValidator
{
    private sealed record RecoveryStateContract(
        string PdfStatus,
        long InventoryBytes,
        string InventoryHash,
        long RawTreeFiles,
        long RawTreeBytes,
        string RawTreeHash);

    private static RecoveryStateContract ValidateRecoveryState(JsonElement root)
    {
        var topProperties = root.EnumerateObject().ToArray();
        var topKeys = topProperties.Select(property => property.Name).ToHashSet();
        if (topProperties.Length != topKeys.Count || !topKeys.SetEquals(new[]
            {
                "schema_version", "contract", "status", "completed_utc", "pdf",
                "source_snapshot", "aggregates", "artifacts",
            }) ||
            root.GetProperty("schema_version").GetInt32() != 2 ||
            root.GetProperty("contract").GetString() != "tvtime-recovery-state-v0.2" ||
            root.GetProperty("status").GetString() != "complete" ||
            !IsCanonicalUtcTimestamp(root.GetProperty("completed_utc")))
        {
            throw InvalidOutput();
        }

        var pdfStatus = ValidatePdfState(root.GetProperty("pdf"));
        var sourceSnapshot = RequireExactObject(
            root.GetProperty("source_snapshot"), "contract", "inventory", "raw_tree");
        if (sourceSnapshot.GetProperty("contract").GetString() !=
            "tvtime-source-snapshot-v0.2")
            throw InvalidOutput();
        var inventoryIdentity = RequireExactObject(
            sourceSnapshot.GetProperty("inventory"), "bytes", "sha256");
        var rawTreeIdentity = RequireExactObject(
            sourceSnapshot.GetProperty("raw_tree"), "files", "bytes", "sha256");
        var inventoryBytes = RequireInteger(
            inventoryIdentity,
            "bytes",
            1,
            RecoveryArtifactContract.MaximumInventoryBytes);
        var inventoryHash = RequireLowercaseSha256(inventoryIdentity, "sha256");
        var rawTreeFiles = RequireInteger(
            rawTreeIdentity, "files", 0, MaximumRawTreeEntries);
        var rawTreeBytes = RequireInteger(rawTreeIdentity, "bytes", 0, long.MaxValue);
        var rawTreeHash = RequireLowercaseSha256(rawTreeIdentity, "sha256");

        ValidateAggregates(root.GetProperty("aggregates"), pdfStatus, rawTreeFiles, rawTreeBytes);
        return new RecoveryStateContract(
            pdfStatus,
            inventoryBytes,
            inventoryHash,
            rawTreeFiles,
            rawTreeBytes,
            rawTreeHash);
    }

    private static string ValidatePdfState(JsonElement pdf)
    {
        var properties = pdf.EnumerateObject().ToArray();
        var keys = properties.Select(property => property.Name).ToHashSet();
        if (properties.Length != keys.Count ||
            !keys.SetEquals(new[] { "status", "artifact_id" }))
            throw InvalidOutput();
        var status = pdf.GetProperty("status").GetString();
        var artifact = pdf.GetProperty("artifact_id");
        if (status is not ("generated" or "omitted") ||
            (status == "generated" && artifact.GetString() != "pdf_report") ||
            (status == "omitted" && artifact.ValueKind != JsonValueKind.Null))
            throw InvalidOutput();
        return status;
    }

    private static void ValidateAggregates(
        JsonElement aggregatesValue,
        string pdfStatus,
        long rawTreeFiles,
        long rawTreeBytes)
    {
        var aggregates = RequireExactObject(
            aggregatesValue, "extraction", "analysis", "report");
        ValidateExtractionAggregate(aggregates.GetProperty("extraction"), rawTreeFiles, rawTreeBytes);
        ValidateAnalysisAggregate(aggregates.GetProperty("analysis"));
        ValidateReportAggregate(aggregates.GetProperty("report"), pdfStatus);
    }

    private static void ValidateExtractionAggregate(
        JsonElement value, long rawTreeFiles, long rawTreeBytes)
    {
        var aggregate = RequireExactObject(
            value, "files_expected", "files_extracted", "bytes_extracted",
            "selected_declared_bytes", "size_discrepancy_count");
        var filesExpected = RequireInteger(
            aggregate, "files_expected", 0, MaximumRawTreeEntries);
        var filesExtracted = RequireInteger(
            aggregate, "files_extracted", 0, MaximumRawTreeEntries);
        var bytesExtracted = RequireInteger(
            aggregate, "bytes_extracted", 0, long.MaxValue);
        _ = RequireInteger(aggregate, "selected_declared_bytes", 0, long.MaxValue);
        var discrepancyCount = RequireInteger(
            aggregate,
            "size_discrepancy_count",
            0,
            Math.Min(filesExpected, MaximumVisualRowsPerTable));
        if (filesExpected != filesExtracted || filesExtracted != rawTreeFiles ||
            bytesExtracted != rawTreeBytes || discrepancyCount > filesExpected)
            throw InvalidOutput();
    }

    private static void ValidateAnalysisAggregate(JsonElement value)
    {
        var aggregate = RequireExactObject(
            value, "series_library", "watched_movies", "movie_watchlist", "favorite_shows",
            "favorite_movies", "watch_events", "watch_events_with_titles",
            "episode_cache_unique", "parser_status");
        var counts = new[]
        {
            RequireInteger(aggregate, "series_library", 0, MaximumVisualRowsPerTable),
            RequireInteger(aggregate, "watched_movies", 0, MaximumVisualRowsPerTable),
            RequireInteger(aggregate, "movie_watchlist", 0, MaximumVisualRowsPerTable),
            RequireInteger(aggregate, "favorite_shows", 0, MaximumVisualRowsPerTable),
            RequireInteger(aggregate, "favorite_movies", 0, MaximumVisualRowsPerTable),
            RequireInteger(aggregate, "watch_events", 0, MaximumVisualRowsPerTable),
            RequireInteger(aggregate, "episode_cache_unique", 0, MaximumVisualRowsPerTable),
        };
        var watchEventsWithTitles = RequireInteger(
            aggregate, "watch_events_with_titles", 0, MaximumVisualRowsPerTable);
        var parserStatus = aggregate.GetProperty("parser_status").GetString();
        if (counts.Sum() > MaximumCombinedVisualRows ||
            watchEventsWithTitles > counts[5] ||
            parserStatus is not ("recognized" or "empty"))
            throw InvalidOutput();
    }

    private static void ValidateReportAggregate(JsonElement value, string pdfStatus)
    {
        var expectedKeys = pdfStatus == "omitted"
            ? new[]
            {
                "image_cache_references", "trailer_references", "media_urls", "pdf_status",
                "pdf_omission_reason",
            }
            : new[]
            {
                "image_cache_references", "trailer_references", "media_urls", "pdf_status",
            };
        var aggregate = RequireExactObject(value, expectedKeys);
        _ = RequireInteger(
            aggregate, "image_cache_references", 0, MaximumVisualRowsPerTable);
        var trailerReferences = RequireInteger(
            aggregate, "trailer_references", 0, MaximumMediaReferenceOccurrences);
        var mediaUrls = RequireInteger(
            aggregate,
            "media_urls",
            0,
            MaximumMediaReferenceOccurrences - trailerReferences);
        if (trailerReferences + mediaUrls > MaximumMediaReferenceOccurrences ||
            aggregate.GetProperty("pdf_status").GetString() != pdfStatus)
            throw InvalidOutput();
        if (pdfStatus == "omitted" &&
            !IsSafeOmissionReason(aggregate.GetProperty("pdf_omission_reason")))
            throw InvalidOutput();
    }
}
