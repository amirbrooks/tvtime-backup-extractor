using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TVTimeRecovery.Windows;

internal static partial class RecoveryOutputValidator
{
    private const int MaximumRawTreeEntries = 100_000;
    private const int MaximumVisualRowsPerTable = 25_000;
    private const int MaximumCombinedVisualRows = 50_000;
    private const int MaximumMediaReferenceOccurrences = 100_000;
    internal static ValidatedRecoveryOutput ValidateCompletedOutput(
        string output,
        CancellationToken cancellationToken = default)
    {
        var extraction = Path.Combine(output, "TVTime-Extraction");
        var analysis = Path.Combine(extraction, "analysis");
        var markerPath = Path.Combine(extraction, "analysis", "recovery_state.json");
        var leases = new List<IDisposable>();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            leases.Add(PinnedRecoveryFile.OpenDirectory(output));
            leases.Add(PinnedRecoveryFile.OpenDirectory(extraction));
            leases.Add(PinnedRecoveryFile.OpenDirectory(analysis));
            if (!Directory.Exists(output) || IsReparse(output) ||
                Directory.GetFileSystemEntries(output).Length != 1 ||
                !Directory.Exists(extraction) || IsReparse(extraction))
            {
                throw InvalidOutput();
            }
            var markerFile = PinnedRecoveryFile.Open(
                markerPath, output, (int)RecoveryArtifactContract.MaximumStateBytes);
            leases.Add(markerFile);
            var markerStream = markerFile.Stream;
            if (markerStream.Length is <= 0 or > RecoveryArtifactContract.MaximumStateBytes)
                throw InvalidOutput();
            var markerPayload = ReadExactPayload(markerStream, cancellationToken);
            using var marker = JsonDocument.Parse(
                markerPayload, new JsonDocumentOptions { MaxDepth = 32 });
            var root = marker.RootElement;
            var state = ValidateRecoveryState(root);
            var validatedArtifacts = ValidateArtifacts(
                root.GetProperty("artifacts"), extraction, state, leases, cancellationToken);
            ValidateSealedRawTree(
                extraction,
                state.InventoryBytes,
                state.InventoryHash,
                state.RawTreeFiles,
                state.RawTreeBytes,
                state.RawTreeHash,
                cancellationToken);

            RequireExactDirectoryMembers(
                extraction,
                new[] { "analysis", "manifest", "metadata", "raw" },
                cancellationToken);
            RequireExactDirectoryMembers(
                Path.Combine(extraction, "manifest"),
                Array.Empty<string>(),
                cancellationToken);
            RequireExactDirectoryMembers(
                Path.Combine(extraction, "metadata"),
                validatedArtifacts.ExpectedPaths.Values
                    .Where(path => path.StartsWith("metadata/", StringComparison.Ordinal))
                    .Select(Path.GetFileName),
                cancellationToken);
            RequireExactDirectoryMembers(
                Path.Combine(extraction, "analysis"),
                validatedArtifacts.ExpectedPaths.Values
                    .Where(path => path.StartsWith("analysis/", StringComparison.Ordinal))
                    .Select(Path.GetFileName)
                    .Append("recovery_state.json"),
                cancellationToken);
            RejectReparseTree(Path.Combine(extraction, "raw"), cancellationToken);
            markerStream.Position = 0;
            var finalMarkerPayload = ReadExactPayload(markerStream, cancellationToken);
            markerFile.EnsureIdentity();
            if (!markerPayload.AsSpan().SequenceEqual(finalMarkerPayload))
                throw InvalidOutput();
            return new ValidatedRecoveryOutput(
                output,
                validatedArtifacts.MarkdownReport,
                validatedArtifacts.HtmlReport,
                leases);
        }
        catch
        {
            for (var index = leases.Count - 1; index >= 0; index--) leases[index].Dispose();
            throw;
        }
    }

    private static byte[] ReadExactPayload(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        if (stream.Length > int.MaxValue) throw InvalidOutput();
        var payload = new byte[(int)stream.Length];
        var offset = 0;
        while (offset < payload.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = stream.Read(payload, offset, payload.Length - offset);
            if (count == 0) throw InvalidOutput();
            offset += count;
        }
        return payload;
    }

    private static string HashStream(FileStream stream, CancellationToken cancellationToken)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = stream.Read(buffer, 0, buffer.Length);
            if (count == 0) break;
            digest.AppendData(buffer, 0, count);
        }
        return Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
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

    private static void RequireExactDirectoryMembers(
        string directory,
        IEnumerable<string?> expected,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
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
            cancellationToken.ThrowIfCancellationRequested();
            if (IsReparse(member)) throw InvalidOutput();
        }
    }

    private static void RejectReparseTree(string rawRoot, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(rawRoot) || IsReparse(rawRoot)) throw InvalidOutput();
        var pending = new Stack<string>();
        pending.Push(rawRoot);
        var entries = 0;
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var member in Directory.GetFileSystemEntries(pending.Pop()))
            {
                cancellationToken.ThrowIfCancellationRequested();
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

    private static RecoveryUserException InvalidOutput()
    {
        return new RecoveryUserException(
            "The recovered output could not be validated completely.",
            RecoveryDiagnostic.OutputValidationFailed);
    }
}
