using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Windows.Storage;

namespace TVTimeRecovery.Windows;

internal enum RecoveryDiagnostic
{
    PreflightStarted,
    PreflightCompleted,
    RecoveryStarted,
    RecoveryCompleted,
    RecoveryCancelled,
    DestinationUnencrypted,
    BackupRejected,
    OutputValidationFailed,
    LocalHelperError,
    UnrecognizedFailure,
}

internal static class RecoveryDiagnostics
{
    public static void Record(RecoveryDiagnostic diagnostic)
    {
        // Deliberately local and value-free. No paths, identifiers, counts,
        // exceptions, helper output, or recovered content are persisted.
        Debug.WriteLine($"RecoveryDiagnostics:{diagnostic}");
    }
}

internal sealed class RecoveryUserException : Exception
{
    public string SafeMessage { get; }
    public RecoveryDiagnostic Diagnostic { get; }

    public RecoveryUserException(string safeMessage, RecoveryDiagnostic diagnostic)
        : base("A privacy-safe recovery error occurred.")
    {
        SafeMessage = safeMessage;
        Diagnostic = diagnostic;
    }
}

internal sealed class ValidatedRecoveryOutput : IDisposable
{
    private readonly IReadOnlyList<IDisposable> _leases;
    private int _disposed;

    public string OutputRoot { get; }
    public string MarkdownReport { get; }
    public string HtmlReport { get; }

    public ValidatedRecoveryOutput(
        string outputRoot,
        string markdownReport,
        string htmlReport,
        IReadOnlyList<IDisposable> leases)
    {
        OutputRoot = outputRoot;
        MarkdownReport = markdownReport;
        HtmlReport = htmlReport;
        _leases = leases;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        for (var index = _leases.Count - 1; index >= 0; index--) _leases[index].Dispose();
    }
}

internal static class PrivateRecoveryStore
{
    public static string RequireEncryptedParent()
    {
        var root = ApplicationData.Current.LocalFolder.Path;
        var drive = Path.GetPathRoot(root);
        if (string.IsNullOrWhiteSpace(drive) || !BitLockerProtection.IsEnabled(drive))
        {
            throw new RecoveryUserException(
                "Windows device encryption or BitLocker protection is not active. Enable it before recovering private data.",
                RecoveryDiagnostic.DestinationUnencrypted);
        }
        var parent = Path.Combine(root, "Private Recoveries");
        Directory.CreateDirectory(parent);
        var attributes = File.GetAttributes(parent);
        if ((attributes & System.IO.FileAttributes.ReparsePoint) != 0)
        {
            throw new RecoveryUserException(
                "The app-managed recovery location could not be verified as private local storage.",
                RecoveryDiagnostic.DestinationUnencrypted);
        }
        return parent;
    }

    public static string FreshOutput(string parent)
    {
        return Path.Combine(parent, $"Recovery-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}");
    }
}

internal static class BitLockerProtection
{
    public static bool IsEnabled(string drive)
    {
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var executable = Path.Combine(systemRoot, "System32", "manage-bde.exe");
        if (!File.Exists(executable))
        {
            return false;
        }
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = executable,
                ArgumentList = { "-status", drive, "-protectionaserrorlevel" },
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (process is null) return false;
            process.OutputDataReceived += static (_, _) => { };
            process.ErrorDataReceived += static (_, _) => { };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            if (!process.WaitForExit(10_000))
            {
                process?.Kill(entireProcessTree: true);
                return false;
            }
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}

internal sealed class RecoveryCoordinator
{
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int ProtocolVersion = 3;
    private const int MaximumRawTreeEntries = 100_000;
    private const int MaximumVisualRowsPerTable = 25_000;
    private const int MaximumCombinedVisualRows = 50_000;
    private const int MaximumMediaReferenceOccurrences = 100_000;
    private static readonly string[] InventoryFields =
    {
        "file_id", "domain", "relative_path", "declared_size", "actual_size",
        "size_match", "mtime", "sha256",
    };
    private static readonly HashSet<string> WindowsReservedNames = new(
        new[]
        {
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
            "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
            "LPT6", "LPT7", "LPT8", "LPT9",
        },
        StringComparer.OrdinalIgnoreCase);
    private static readonly IReadOnlyDictionary<string, string> RequiredArtifacts =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["extraction_run_state"] = "metadata/run_state.json",
            ["extraction_inventory"] = "metadata/inventory.csv",
            ["extraction_summary"] = "metadata/summary.json",
            ["extraction_domains"] = "metadata/domains.txt",
            ["analysis_summary"] = "analysis/analysis_summary.json",
            ["cache_index"] = "analysis/cache_index.csv",
            ["movie_library"] = "analysis/movie_library.csv",
            ["watch_events"] = "analysis/watch_events.csv",
            ["episode_cache"] = "analysis/episode_cache.csv",
            ["sqlite_integrity"] = "analysis/sqlite_integrity.csv",
            ["plist_key_inventory"] = "analysis/plist_key_inventory.csv",
            ["series_library"] = "analysis/series_library.csv",
            ["watched_movies"] = "analysis/watched_movies.csv",
            ["movie_watchlist"] = "analysis/movie_watchlist.csv",
            ["favorite_shows"] = "analysis/favorite_shows.csv",
            ["favorite_movies"] = "analysis/favorite_movies.csv",
            ["episode_cache_unique"] = "analysis/episode_cache_unique.csv",
            ["watch_events_named"] = "analysis/watch_events_named.csv",
            ["trailer_references"] = "analysis/trailer_references.csv",
            ["media_url_inventory"] = "analysis/media_url_inventory.csv",
            ["image_cache_references"] = "analysis/image_cache_references.csv",
            ["markdown_report"] = "analysis/TVTime-Recovered-Data.md",
            ["html_report"] = "analysis/TVTime-Recovered-Data.html",
        };

    public async Task<ValidatedRecoveryOutput> RecoverAsync(
        string sourceKind,
        string backup,
        string output,
        string password,
        Action<string> progress,
        CancellationToken cancellationToken)
    {
        if (sourceKind is not (
            "ios_encrypted_backup" or "android_legacy_backup" or "android_preserved_snapshot" or
            "tvtime_official_export"))
        {
            throw new RecoveryUserException(
                "The selected recovery source is not supported by this private installation.",
                RecoveryDiagnostic.BackupRejected);
        }
        var helper = Path.Combine(AppContext.BaseDirectory, "Helpers", "tvtime-helper.exe");
        if (!File.Exists(helper))
        {
            throw new RecoveryUserException(
                "The private recovery helper is unavailable. Reinstall the private app package.",
                RecoveryDiagnostic.LocalHelperError);
        }
        var parent = Path.GetDirectoryName(output) ?? throw new RecoveryUserException(
            "The app-managed recovery location was unavailable.",
            RecoveryDiagnostic.DestinationUnencrypted);

        if (sourceKind == "ios_encrypted_backup")
        {
            await RecoverEncryptedIosAsync(
                helper, backup, output, parent, password, progress, cancellationToken);
        }
        else
        {
            await AcquireAsync(
                helper, sourceKind, backup, output, parent, password, progress, cancellationToken);
        }
        return ValidateCompletedOutput(output);
    }

    private static async Task RecoverEncryptedIosAsync(
        string helper,
        string backup,
        string output,
        string parent,
        string password,
        Action<string> progress,
        CancellationToken cancellationToken)
    {
        if (password.Length == 0)
        {
            throw new RecoveryUserException(
                "Enter the encrypted local-backup password before recovery.",
                RecoveryDiagnostic.BackupRejected);
        }

        RecoveryDiagnostics.Record(RecoveryDiagnostic.PreflightStarted);
        progress("Validating the completed encrypted backup…");
        JsonElement receipt;
        await using (var preflight = NativeHelperProcess.Start(helper, parent))
        {
            var payload = EncryptedIosPayload(
                backup, output, preflight.DestinationIdentity, receipt: null);
            await preflight.SendControlAsync(
                EncryptedIosRequest("preflight", payload),
                cancellationToken);
            var completed = await ReadToCompletionAsync(preflight, progress, cancellationToken);
            if (!completed.TryGetProperty("backup_receipt", out var receiptValue) ||
                receiptValue.ValueKind != JsonValueKind.Object)
            {
                throw new RecoveryUserException(
                    "The private helper did not return a valid backup confirmation.",
                    RecoveryDiagnostic.LocalHelperError);
            }
            receipt = receiptValue.Clone();
        }
        RecoveryDiagnostics.Record(RecoveryDiagnostic.PreflightCompleted);

        RecoveryDiagnostics.Record(RecoveryDiagnostic.RecoveryStarted);
        progress("Unlocking and recovering the encrypted backup…");
        await using var recovery = NativeHelperProcess.Start(helper, parent);
        var recoveryPayload = EncryptedIosPayload(
            backup, output, recovery.DestinationIdentity, receipt);
        await recovery.SendControlAsync(
            EncryptedIosRequest("recover", recoveryPayload),
            cancellationToken);
        await recovery.SendSecretAsync(password, cancellationToken);
        await ReadToCompletionAsync(recovery, progress, cancellationToken);
    }

    private static Dictionary<string, object?> EncryptedIosPayload(
        string backup,
        string output,
        DestinationIdentity destination,
        JsonElement? receipt)
    {
        return new Dictionary<string, object?>
        {
            ["backup_directory"] = backup,
            ["output_directory"] = output,
            ["destination_parent_identity"] = new Dictionary<string, ulong>
            {
                ["device"] = destination.Device,
                ["inode"] = destination.Inode,
            },
            ["acknowledge_sensitive_output"] = true,
            ["include_raw_cache"] = false,
            ["include_decrypted_manifest"] = false,
            ["backup_receipt"] = receipt,
        };
    }

    private static byte[] EncryptedIosRequest(
        string action,
        Dictionary<string, object?> payload)
    {
        return JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?>
        {
            ["protocolVersion"] = ProtocolVersion,
            ["type"] = action,
            ["payload"] = payload,
        });
    }

    private static async Task AcquireAsync(
        string helper,
        string sourceKind,
        string source,
        string output,
        string parent,
        string sourcePassword,
        Action<string> progress,
        CancellationToken cancellationToken)
    {
        if (sourceKind is not (
            "android_legacy_backup" or "android_preserved_snapshot" or "tvtime_official_export"))
        {
            throw new RecoveryUserException(
                "The selected recovery source is not supported by this private installation.",
                RecoveryDiagnostic.BackupRejected);
        }
        RecoveryDiagnostics.Record(RecoveryDiagnostic.RecoveryStarted);
        progress("Validating and recovering the selected private source…");
        await using var acquisition = NativeHelperProcess.Start(helper, parent);
        var hasSecret = sourceKind == "tvtime_official_export" && sourcePassword.Length > 0;
        var payload = new Dictionary<string, object?>
        {
            ["source_kind"] = sourceKind,
            ["source_path"] = source,
            ["output_directory"] = output,
            ["destination_parent_identity"] = new Dictionary<string, ulong>
            {
                ["device"] = acquisition.DestinationIdentity.Device,
                ["inode"] = acquisition.DestinationIdentity.Inode,
            },
            ["acknowledge_sensitive_output"] = true,
            ["include_raw_cache"] = false,
            ["has_source_secret"] = hasSecret,
        };
        var request = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?>
        {
            ["protocolVersion"] = ProtocolVersion,
            ["type"] = "acquire",
            ["payload"] = payload,
        });
        await acquisition.SendControlAsync(request, cancellationToken);
        if (hasSecret) await acquisition.SendSecretAsync(sourcePassword, cancellationToken);
        await ReadToCompletionAsync(acquisition, progress, cancellationToken);
    }

    private static async Task<JsonElement> ReadToCompletionAsync(
        NativeHelperProcess helper,
        Action<string> progress,
        CancellationToken cancellationToken)
    {
        using var cancellationRegistration = cancellationToken.Register(
            static state => _ = ((NativeHelperProcess)state!).CancelAsync(), helper);
        var expectedSequence = 1;
        await foreach (var document in helper.EventsAsync(cancellationToken))
        {
            using (document)
            {
                var root = document.RootElement;
                if (root.GetProperty("protocolVersion").GetInt32() != ProtocolVersion ||
                    root.GetProperty("sequence").GetInt32() != expectedSequence++)
                {
                    throw new RecoveryUserException(
                        "The app and private helper protocol did not match.",
                        RecoveryDiagnostic.LocalHelperError);
                }
                var type = root.GetProperty("type").GetString();
                if (type == "progress")
                {
                    var stage = root.GetProperty("payload").GetProperty("stage").GetString();
                    progress(stage switch
                    {
                        "extraction" => "Copying selected TV Time files…",
                        "analysis" => "Recovering readable history tables…",
                        "report" => "Building private offline reports…",
                        _ => "Validating private recovery state…",
                    });
                }
                else if (type == "completed")
                {
                    var completion = root.GetProperty("payload").Clone();
                    await helper.WaitForSuccessfulExitAsync();
                    return completion;
                }
                else if (type is "failed" or "cancelled")
                {
                    var code = root.GetProperty("payload").GetProperty("code").GetString();
                    throw SafeFailure(code);
                }
            }
        }
        throw new RecoveryUserException(
            "The private helper ended before recovery completed.",
            RecoveryDiagnostic.LocalHelperError);
    }

    private static RecoveryUserException SafeFailure(string? code)
    {
        return code switch
        {
            "backup_unencrypted" => new("The selected Apple backup is not encrypted.", RecoveryDiagnostic.BackupRejected),
            "backup_unfinished" => new("The selected Apple backup is not marked finished.", RecoveryDiagnostic.BackupRejected),
            "backup_password_rejected" => new("The encrypted backup password was not accepted.", RecoveryDiagnostic.BackupRejected),
            "cancelled" => new("Recovery was cancelled and incomplete output was preserved.", RecoveryDiagnostic.RecoveryCancelled),
            _ => new("Recovery stopped safely before a completed report was accepted.", RecoveryDiagnostic.LocalHelperError),
        };
    }

    internal static ValidatedRecoveryOutput ValidateCompletedOutput(string output)
    {
        var extraction = Path.Combine(output, "TVTime-Extraction");
        var analysis = Path.Combine(extraction, "analysis");
        var markerPath = Path.Combine(extraction, "analysis", "recovery_state.json");
        var leases = new List<IDisposable>();
        try
        {
            leases.Add(OpenPinnedDirectory(output));
            leases.Add(OpenPinnedDirectory(extraction));
            leases.Add(OpenPinnedDirectory(analysis));
            if (!Directory.Exists(output) || IsReparse(output) ||
                Directory.GetFileSystemEntries(output).Length != 1 ||
                !Directory.Exists(extraction) || IsReparse(extraction) || !File.Exists(markerPath) ||
                IsReparse(markerPath))
            {
                throw InvalidOutput();
            }
            var markerStream = new FileStream(
                markerPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                FileOptions.SequentialScan);
            leases.Add(markerStream);
            if (markerStream.Length is <= 0 or > 64 * 1024) throw InvalidOutput();
            var markerPayload = ReadExactPayload(markerStream);
            using var marker = JsonDocument.Parse(
                markerPayload, new JsonDocumentOptions { MaxDepth = 32 });
        var root = marker.RootElement;
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
        var pdf = root.GetProperty("pdf");
        var pdfProperties = pdf.EnumerateObject().ToArray();
        var pdfKeys = pdfProperties.Select(property => property.Name).ToHashSet();
        if (pdfProperties.Length != pdfKeys.Count ||
            !pdfKeys.SetEquals(new[] { "status", "artifact_id" })) throw InvalidOutput();
        var pdfStatus = pdf.GetProperty("status").GetString();
        var pdfArtifact = pdf.GetProperty("artifact_id");
        if (pdfStatus is not ("generated" or "omitted") ||
            (pdfStatus == "generated" && pdfArtifact.GetString() != "pdf_report") ||
            (pdfStatus == "omitted" && pdfArtifact.ValueKind != JsonValueKind.Null))
            throw InvalidOutput();

        var sourceSnapshot = RequireExactObject(
            root.GetProperty("source_snapshot"), "contract", "inventory", "raw_tree");
        if (sourceSnapshot.GetProperty("contract").GetString() != "tvtime-source-snapshot-v0.2")
            throw InvalidOutput();
        var inventoryIdentity = RequireExactObject(
            sourceSnapshot.GetProperty("inventory"), "bytes", "sha256");
        var rawTreeIdentity = RequireExactObject(
            sourceSnapshot.GetProperty("raw_tree"), "files", "bytes", "sha256");
        var inventoryBytes = RequireInteger(inventoryIdentity, "bytes", 1, 256L * 1024 * 1024);
        var inventoryHash = RequireLowercaseSha256(inventoryIdentity, "sha256");
        var rawTreeFiles = RequireInteger(rawTreeIdentity, "files", 0, MaximumRawTreeEntries);
        var rawTreeBytes = RequireInteger(rawTreeIdentity, "bytes", 0, long.MaxValue);
        _ = RequireLowercaseSha256(rawTreeIdentity, "sha256");

        var aggregates = RequireExactObject(
            root.GetProperty("aggregates"), "extraction", "analysis", "report");
        var extractionAggregate = RequireExactObject(
            aggregates.GetProperty("extraction"), "files_expected", "files_extracted",
            "bytes_extracted", "selected_declared_bytes", "size_discrepancy_count");
        var filesExpected = RequireInteger(
            extractionAggregate, "files_expected", 0, MaximumRawTreeEntries);
        var filesExtracted = RequireInteger(
            extractionAggregate, "files_extracted", 0, MaximumRawTreeEntries);
        var bytesExtracted = RequireInteger(
            extractionAggregate, "bytes_extracted", 0, long.MaxValue);
        _ = RequireInteger(extractionAggregate, "selected_declared_bytes", 0, long.MaxValue);
        var discrepancyCount = RequireInteger(
            extractionAggregate, "size_discrepancy_count", 0,
            Math.Min(filesExpected, MaximumVisualRowsPerTable));
        if (filesExpected != filesExtracted || filesExtracted != rawTreeFiles ||
            bytesExtracted != rawTreeBytes || discrepancyCount > filesExpected)
            throw InvalidOutput();

        var analysisAggregate = RequireExactObject(
            aggregates.GetProperty("analysis"), "series_library", "watched_movies",
            "movie_watchlist", "favorite_shows", "favorite_movies", "watch_events",
            "watch_events_with_titles", "episode_cache_unique", "parser_status");
        var analysisCounts = new[]
        {
            RequireInteger(analysisAggregate, "series_library", 0, MaximumVisualRowsPerTable),
            RequireInteger(analysisAggregate, "watched_movies", 0, MaximumVisualRowsPerTable),
            RequireInteger(analysisAggregate, "movie_watchlist", 0, MaximumVisualRowsPerTable),
            RequireInteger(analysisAggregate, "favorite_shows", 0, MaximumVisualRowsPerTable),
            RequireInteger(analysisAggregate, "favorite_movies", 0, MaximumVisualRowsPerTable),
            RequireInteger(analysisAggregate, "watch_events", 0, MaximumVisualRowsPerTable),
            RequireInteger(analysisAggregate, "episode_cache_unique", 0, MaximumVisualRowsPerTable),
        };
        var watchEventsWithTitles = RequireInteger(
            analysisAggregate, "watch_events_with_titles", 0, MaximumVisualRowsPerTable);
        var parserStatus = analysisAggregate.GetProperty("parser_status").GetString();
        if (analysisCounts.Sum() > MaximumCombinedVisualRows ||
            watchEventsWithTitles > analysisCounts[5] ||
            parserStatus is not ("recognized" or "empty"))
            throw InvalidOutput();

        var expectedReportKeys = pdfStatus == "omitted"
            ? new[] { "image_cache_references", "trailer_references", "media_urls", "pdf_status", "pdf_omission_reason" }
            : new[] { "image_cache_references", "trailer_references", "media_urls", "pdf_status" };
        var reportAggregate = RequireExactObject(
            aggregates.GetProperty("report"), expectedReportKeys);
        _ = RequireInteger(
            reportAggregate, "image_cache_references", 0, MaximumVisualRowsPerTable);
        var trailerReferences = RequireInteger(
            reportAggregate, "trailer_references", 0, MaximumMediaReferenceOccurrences);
        var mediaUrls = RequireInteger(
            reportAggregate, "media_urls", 0,
            MaximumMediaReferenceOccurrences - trailerReferences);
        if (trailerReferences + mediaUrls > MaximumMediaReferenceOccurrences ||
            reportAggregate.GetProperty("pdf_status").GetString() != pdfStatus)
            throw InvalidOutput();
        if (pdfStatus == "omitted" &&
            !IsSafeOmissionReason(reportAggregate.GetProperty("pdf_omission_reason")))
            throw InvalidOutput();

        var expectedArtifacts = new Dictionary<string, string>(RequiredArtifacts, StringComparer.Ordinal);
        if (pdfStatus == "generated")
            expectedArtifacts["pdf_report"] = "analysis/TVTime-Recovered-Data.pdf";
        var artifacts = root.GetProperty("artifacts");
        if (artifacts.ValueKind != JsonValueKind.Array ||
            artifacts.GetArrayLength() != expectedArtifacts.Count)
            throw InvalidOutput();
        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        var artifactIdentities = new Dictionary<string, (long Bytes, string Hash)>(
            StringComparer.Ordinal);
        string? markdownReport = null;
        string? htmlReport = null;
        foreach (var binding in artifacts.EnumerateArray())
        {
            var properties = binding.EnumerateObject().ToArray();
            var keys = properties.Select(property => property.Name).ToHashSet();
            if (properties.Length != keys.Count ||
                !keys.SetEquals(new[] { "id", "relative_path", "bytes", "sha256" }))
                throw InvalidOutput();
            var identifier = binding.GetProperty("id").GetString();
            var relative = binding.GetProperty("relative_path").GetString();
            var expectedBytes = binding.GetProperty("bytes").GetInt64();
            var expectedHash = binding.GetProperty("sha256").GetString();
            if (string.IsNullOrEmpty(identifier) || !identifiers.Add(identifier) ||
                !expectedArtifacts.TryGetValue(identifier, out var expectedRelative) ||
                relative != expectedRelative || string.IsNullOrEmpty(relative) || Path.IsPathRooted(relative) ||
                relative.Contains('\\') || relative.Split('/').Any(part => part is "" or "." or "..") ||
                expectedBytes < 0 || expectedHash is null ||
                !Regex.IsMatch(expectedHash, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant))
            {
                throw InvalidOutput();
            }
            var path = Path.GetFullPath(Path.Combine(extraction, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!path.StartsWith(extraction + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(path) || HasReparseAncestor(path, extraction) ||
                IsReparse(path))
                throw InvalidOutput();
            FileStream? stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024,
                FileOptions.SequentialScan);
            try
            {
                if (stream.Length != expectedBytes || IsReparse(path)) throw InvalidOutput();
                var actualHash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
                if (!CryptographicOperations.FixedTimeEquals(
                        Encoding.ASCII.GetBytes(actualHash), Encoding.ASCII.GetBytes(expectedHash)))
                    throw InvalidOutput();
                if (identifier == "markdown_report") markdownReport = path;
                if (identifier == "html_report") htmlReport = path;
                if (identifier is "markdown_report" or "html_report")
                {
                    leases.Add(stream);
                    stream = null;
                }
            }
            finally
            {
                stream?.Dispose();
            }
            artifactIdentities.Add(identifier, (expectedBytes, expectedHash));
        }
        if (!identifiers.SetEquals(expectedArtifacts.Keys) || markdownReport is null ||
            htmlReport is null) throw InvalidOutput();
        if (!artifactIdentities.TryGetValue("extraction_inventory", out var sealedInventory) ||
            sealedInventory.Bytes != inventoryBytes || sealedInventory.Hash != inventoryHash)
            throw InvalidOutput();

        ValidateSealedRawTree(
            extraction, inventoryBytes, inventoryHash, rawTreeFiles, rawTreeBytes,
            rawTreeIdentity.GetProperty("sha256").GetString()!);

        RequireExactDirectoryMembers(
            extraction, new[] { "analysis", "manifest", "metadata", "raw" });
        RequireExactDirectoryMembers(Path.Combine(extraction, "manifest"), Array.Empty<string>());
        RequireExactDirectoryMembers(
            Path.Combine(extraction, "metadata"),
            expectedArtifacts.Values
                .Where(path => path.StartsWith("metadata/", StringComparison.Ordinal))
                .Select(Path.GetFileName));
        RequireExactDirectoryMembers(
            Path.Combine(extraction, "analysis"),
            expectedArtifacts.Values
                .Where(path => path.StartsWith("analysis/", StringComparison.Ordinal))
                .Select(Path.GetFileName)
                .Append("recovery_state.json"));
        RejectReparseTree(Path.Combine(extraction, "raw"));
        markerStream.Position = 0;
        var finalMarkerPayload = ReadExactPayload(markerStream);
        if (IsReparse(markerPath) || !markerPayload.AsSpan().SequenceEqual(finalMarkerPayload))
            throw InvalidOutput();
            return new ValidatedRecoveryOutput(output, markdownReport, htmlReport, leases);
        }
        catch
        {
            for (var index = leases.Count - 1; index >= 0; index--) leases[index].Dispose();
            throw;
        }
    }

    private static byte[] ReadExactPayload(FileStream stream)
    {
        if (stream.Length > int.MaxValue) throw InvalidOutput();
        var payload = new byte[(int)stream.Length];
        stream.ReadExactly(payload);
        return payload;
    }

    private static SafeFileHandle OpenPinnedDirectory(string path)
    {
        var handle = CreateFileW(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw InvalidOutput();
        }
        if (!GetFileInformationByHandle(handle, out var information) ||
            (information.FileAttributes & FileAttributeDirectory) == 0 ||
            (information.FileAttributes & FileAttributeReparsePoint) != 0)
        {
            handle.Dispose();
            throw InvalidOutput();
        }
        return handle;
    }

    private static JsonElement RequireExactObject(JsonElement value, params string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object) throw InvalidOutput();
        var properties = value.EnumerateObject().ToArray();
        var keys = properties.Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        if (properties.Length != keys.Count || !keys.SetEquals(expected)) throw InvalidOutput();
        return value;
    }

    private static long RequireInteger(
        JsonElement parent, string name, long minimum, long maximum)
    {
        var value = parent.GetProperty(name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var parsed) ||
            parsed < minimum || parsed > maximum)
            throw InvalidOutput();
        return parsed;
    }

    private static string RequireLowercaseSha256(JsonElement parent, string name)
    {
        var value = parent.GetProperty(name);
        var hash = value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        if (hash is null ||
            !Regex.IsMatch(hash, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant))
            throw InvalidOutput();
        return hash;
    }

    private static bool IsCanonicalUtcTimestamp(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String) return false;
        var text = value.GetString();
        return text is not null && text.Length is > 0 and <= 64 && text.EndsWith("+00:00") &&
            !text.Any(char.IsControl) &&
            DateTimeOffset.TryParse(
                text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) &&
            parsed.Offset == TimeSpan.Zero;
    }

    private static bool IsSafeOmissionReason(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String) return false;
        var reason = value.GetString()?.Trim();
        return !string.IsNullOrEmpty(reason) && reason.Length <= 500 &&
            !reason.Any(char.IsControl) && !reason.Contains('/') && !reason.Contains('\\') &&
            !reason.Contains("file:", StringComparison.OrdinalIgnoreCase);
    }

    private sealed record InventoryEntry(string RelativeRawPath, long ActualSize, string Sha256);

    private static void ValidateSealedRawTree(
        string extraction,
        long expectedInventoryBytes,
        string expectedInventoryHash,
        long expectedFileCount,
        long expectedRawBytes,
        string expectedTreeHash)
    {
        var inventoryPath = Path.Combine(extraction, "metadata", "inventory.csv");
        var inventoryPayload = ReadStableRegularFile(
            inventoryPath, expectedInventoryBytes, expectedInventoryHash, capture: true);
        var entries = ParseInventory(inventoryPayload);
        long actualBytes = 0;
        foreach (var entry in entries)
        {
            try { actualBytes = checked(actualBytes + entry.ActualSize); }
            catch (OverflowException) { throw InvalidOutput(); }
        }
        if (entries.Count != expectedFileCount || actualBytes != expectedRawBytes ||
            CanonicalTreeDigest(entries) != expectedTreeHash)
            throw InvalidOutput();

        var rawRoot = Path.Combine(extraction, "raw");
        ValidateRawTreePass(rawRoot, entries);
        ValidateRawTreePass(rawRoot, entries);
        _ = ReadStableRegularFile(
            inventoryPath, expectedInventoryBytes, expectedInventoryHash, capture: false);
    }

    private static byte[] ReadStableRegularFile(
        string path, long expectedBytes, string expectedHash, bool capture)
    {
        if (!File.Exists(path) || IsReparse(path) || expectedBytes is <= 0 or > 256L * 1024 * 1024)
            throw InvalidOutput();
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length != expectedBytes || IsReparse(path)) throw InvalidOutput();
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var captured = capture ? new MemoryStream(checked((int)expectedBytes)) : null;
        var buffer = new byte[128 * 1024];
        long observed = 0;
        while (true)
        {
            var count = stream.Read(buffer, 0, buffer.Length);
            if (count == 0) break;
            observed = checked(observed + count);
            digest.AppendData(buffer, 0, count);
            captured?.Write(buffer, 0, count);
        }
        var observedHash = Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
        if (observed != expectedBytes || stream.Length != expectedBytes || IsReparse(path) ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(observedHash), Encoding.ASCII.GetBytes(expectedHash)))
            throw InvalidOutput();
        return captured?.ToArray() ?? Array.Empty<byte>();
    }

    private static List<InventoryEntry> ParseInventory(byte[] payload)
    {
        string text;
        try { text = new UTF8Encoding(false, true).GetString(payload); }
        catch (DecoderFallbackException) { throw InvalidOutput(); }
        var rows = ParseCsv(text);
        if (rows.Count == 0 || !rows[0].SequenceEqual(InventoryFields, StringComparer.Ordinal) ||
            rows.Count - 1 > MaximumRawTreeEntries)
            throw InvalidOutput();
        var entries = new List<InventoryEntry>(rows.Count - 1);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows.Skip(1))
        {
            if (row.Count != InventoryFields.Length ||
                !Regex.IsMatch(row[0], "^[0-9a-f]{40}$", RegexOptions.CultureInvariant) ||
                !IsPortableComponent(row[1]) || string.IsNullOrEmpty(row[2]) ||
                row[2].Contains('\\') || row[2].StartsWith('/') || row[2].EndsWith('/') ||
                row[2].Split('/').Any(part => !IsPortableComponent(part)) ||
                !TryCanonicalNonnegativeInteger(row[3], out var declaredSize) ||
                !TryCanonicalNonnegativeInteger(row[4], out var actualSize) ||
                row[5] != (declaredSize == actualSize ? "True" : "False") ||
                !Regex.IsMatch(row[7], "^[0-9a-f]{64}$", RegexOptions.CultureInvariant))
                throw InvalidOutput();
            var rawPath = $"{row[1]}/{row[2]}";
            if (!paths.Add(rawPath)) throw InvalidOutput();
            entries.Add(new InventoryEntry(rawPath, actualSize, row[7]));
        }
        entries.Sort(static (left, right) => CompareUtf8(left.RelativeRawPath, right.RelativeRawPath));
        return entries;
    }

    private static List<List<string>> ParseCsv(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        var afterQuote = false;
        var fieldStarted = false;
        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            if (quoted)
            {
                if (character == '"')
                {
                    if (index + 1 < text.Length && text[index + 1] == '"')
                    {
                        field.Append('"');
                        index++;
                    }
                    else
                    {
                        quoted = false;
                        afterQuote = true;
                    }
                }
                else field.Append(character);
                continue;
            }
            if (afterQuote && character is not (',' or '\r' or '\n')) throw InvalidOutput();
            if (character == '"')
            {
                if (fieldStarted || field.Length != 0 || afterQuote) throw InvalidOutput();
                quoted = true;
                fieldStarted = true;
            }
            else if (character == ',')
            {
                row.Add(field.ToString());
                field.Clear();
                fieldStarted = false;
                afterQuote = false;
            }
            else if (character is '\r' or '\n')
            {
                if (character == '\r' && index + 1 < text.Length && text[index + 1] == '\n') index++;
                row.Add(field.ToString());
                rows.Add(row);
                row = new List<string>();
                field.Clear();
                fieldStarted = false;
                afterQuote = false;
            }
            else
            {
                field.Append(character);
                fieldStarted = true;
            }
        }
        if (quoted) throw InvalidOutput();
        if (fieldStarted || afterQuote || field.Length != 0 || row.Count != 0)
        {
            row.Add(field.ToString());
            rows.Add(row);
        }
        return rows;
    }

    private static bool TryCanonicalNonnegativeInteger(string text, out long value)
    {
        value = 0;
        return Regex.IsMatch(text, "^(0|[1-9][0-9]*)$", RegexOptions.CultureInvariant) &&
            long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private static bool IsPortableComponent(string value)
    {
        if (string.IsNullOrEmpty(value) || value is "." or ".." || value.EndsWith(' ') ||
            value.EndsWith('.') || value.Any(character => character < 32) ||
            value.IndexOfAny("<>:\"|?*".ToCharArray()) >= 0)
            return false;
        var baseName = value.Split('.', 2)[0];
        return !WindowsReservedNames.Contains(baseName);
    }

    private static int CompareUtf8(string left, string right)
    {
        return Encoding.UTF8.GetBytes(left).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(right));
    }

    private static string CanonicalTreeDigest(IEnumerable<InventoryEntry> entries)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("tvtime-raw-tree-digest-v0.2\0"u8);
        Span<byte> size = stackalloc byte[8];
        foreach (var entry in entries)
        {
            var path = Encoding.UTF8.GetBytes(entry.RelativeRawPath);
            BinaryPrimitives.WriteUInt64BigEndian(size, (ulong)path.Length);
            digest.AppendData(size);
            digest.AppendData(path);
            BinaryPrimitives.WriteUInt64BigEndian(size, (ulong)entry.ActualSize);
            digest.AppendData(size);
            digest.AppendData(Convert.FromHexString(entry.Sha256));
        }
        return Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
    }

    private static void ValidateRawTreePass(string rawRoot, IReadOnlyList<InventoryEntry> entries)
    {
        if (!Directory.Exists(rawRoot) || IsReparse(rawRoot)) throw InvalidOutput();
        var expectedFiles = entries.ToDictionary(
            entry => entry.RelativeRawPath, entry => entry, StringComparer.OrdinalIgnoreCase);
        if (expectedFiles.Count != entries.Count) throw InvalidOutput();
        var expectedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            var components = entry.RelativeRawPath.Split('/');
            for (var count = 1; count < components.Length; count++)
                expectedDirectories.Add(string.Join('/', components.Take(count)));
        }
        var observedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var observedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<string>();
        pending.Push(rawRoot);
        var observedEntries = 0;
        while (pending.Count > 0)
        {
            foreach (var member in Directory.GetFileSystemEntries(pending.Pop()))
            {
                if (++observedEntries > MaximumRawTreeEntries * 2 || IsReparse(member))
                    throw InvalidOutput();
                var relative = Path.GetRelativePath(rawRoot, member)
                    .Replace(Path.DirectorySeparatorChar, '/');
                if (Directory.Exists(member))
                {
                    if (!observedDirectories.Add(relative)) throw InvalidOutput();
                    pending.Push(member);
                }
                else if (File.Exists(member))
                {
                    if (!observedFiles.Add(relative) ||
                        !expectedFiles.TryGetValue(relative, out var expected))
                        throw InvalidOutput();
                    _ = ReadRawFile(member, expected.ActualSize, expected.Sha256);
                }
                else throw InvalidOutput();
            }
        }
        if (!observedFiles.SetEquals(expectedFiles.Keys) ||
            !observedDirectories.SetEquals(expectedDirectories))
            throw InvalidOutput();
    }

    private static bool ReadRawFile(string path, long expectedBytes, string expectedHash)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length != expectedBytes || IsReparse(path)) throw InvalidOutput();
        var observedHash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (stream.Length != expectedBytes || IsReparse(path) ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(observedHash), Encoding.ASCII.GetBytes(expectedHash)))
            throw InvalidOutput();
        return true;
    }

    private static void RequireExactDirectoryMembers(string directory, IEnumerable<string?> expected)
    {
        if (!Directory.Exists(directory) || IsReparse(directory)) throw InvalidOutput();
        var expectedNames = expected.Select(name => name ?? throw InvalidOutput())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var members = Directory.GetFileSystemEntries(directory);
        var actualNames = members.Select(Path.GetFileName).ToArray();
        if (actualNames.Length != expectedNames.Count ||
            !actualNames.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(expectedNames))
            throw InvalidOutput();
        foreach (var member in members)
        {
            if (IsReparse(member)) throw InvalidOutput();
        }
    }

    private static void RejectReparseTree(string rawRoot)
    {
        if (!Directory.Exists(rawRoot) || IsReparse(rawRoot)) throw InvalidOutput();
        var pending = new Stack<string>();
        pending.Push(rawRoot);
        var entries = 0;
        while (pending.Count > 0)
        {
            foreach (var member in Directory.GetFileSystemEntries(pending.Pop()))
            {
                if (++entries > MaximumRawTreeEntries || IsReparse(member)) throw InvalidOutput();
                if (Directory.Exists(member)) pending.Push(member);
                else if (!File.Exists(member)) throw InvalidOutput();
            }
        }
    }

    private static bool IsReparse(string path) =>
        (File.GetAttributes(path) & System.IO.FileAttributes.ReparsePoint) != 0;

    private static bool HasReparseAncestor(string path, string extraction)
    {
        for (var parent = Directory.GetParent(path); parent is not null; parent = parent.Parent)
        {
            if (IsReparse(parent.FullName)) return true;
            if (string.Equals(parent.FullName, extraction, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileInformation
    {
        public uint FileAttributes;
        public NativeFileTime CreationTime;
        public NativeFileTime LastAccessTime;
        public NativeFileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string name,
        uint access,
        uint share,
        IntPtr security,
        uint creation,
        uint flags,
        IntPtr template);

    [DllImport("kernel32", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out NativeFileInformation information);

    private static RecoveryUserException InvalidOutput()
    {
        return new RecoveryUserException(
            "The recovered output could not be validated completely.",
            RecoveryDiagnostic.OutputValidationFailed);
    }
}
