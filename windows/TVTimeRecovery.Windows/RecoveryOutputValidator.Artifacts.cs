using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TVTimeRecovery.Windows;

internal static partial class RecoveryOutputValidator
{
    private sealed record ValidatedArtifactSet(
        string MarkdownReport,
        string HtmlReport,
        IReadOnlyDictionary<string, string> ExpectedPaths);

    private static ValidatedArtifactSet ValidateArtifacts(
        JsonElement artifacts,
        string extraction,
        RecoveryStateContract state,
        List<IDisposable> leases,
        CancellationToken cancellationToken)
    {
        var expectedArtifacts = new Dictionary<string, string>(
            RecoveryArtifactContract.RequiredArtifacts,
            StringComparer.Ordinal);
        if (state.PdfStatus == "generated")
            expectedArtifacts["pdf_report"] = "analysis/TVTime-Recovered-Data.pdf";
        if (artifacts.ValueKind != JsonValueKind.Array ||
            artifacts.GetArrayLength() != expectedArtifacts.Count)
            throw InvalidOutput();

        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        var identities = new Dictionary<string, (long Bytes, string Hash)>(
            StringComparer.Ordinal);
        string? markdownReport = null;
        string? htmlReport = null;
        foreach (var binding in artifacts.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (identifier, expectedBytes, expectedHash, path) = ValidateArtifactBinding(
                binding, expectedArtifacts, identifiers, extraction);
            ValidateArtifactFile(
                path,
                extraction,
                expectedBytes,
                expectedHash,
                identifier,
                leases,
                cancellationToken);
            if (identifier == "markdown_report") markdownReport = path;
            if (identifier == "html_report") htmlReport = path;
            identities.Add(identifier, (expectedBytes, expectedHash));
        }

        if (!identifiers.SetEquals(expectedArtifacts.Keys) || markdownReport is null ||
            htmlReport is null)
            throw InvalidOutput();
        if (!identities.TryGetValue("extraction_inventory", out var sealedInventory) ||
            sealedInventory.Bytes != state.InventoryBytes ||
            sealedInventory.Hash != state.InventoryHash)
            throw InvalidOutput();
        return new ValidatedArtifactSet(markdownReport, htmlReport, expectedArtifacts);
    }

    private static (string Identifier, long Bytes, string Hash, string Path)
        ValidateArtifactBinding(
            JsonElement binding,
            IReadOnlyDictionary<string, string> expectedArtifacts,
            HashSet<string> identifiers,
            string extraction)
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
            relative != expectedRelative || string.IsNullOrEmpty(relative) ||
            Path.IsPathRooted(relative) || relative.Contains('\\') ||
            relative.Split('/').Any(part => part is "" or "." or "..") ||
            expectedBytes < 0 ||
            expectedBytes > RecoveryArtifactContract.MaximumBytesFor(identifier) ||
            expectedHash is null ||
            !Regex.IsMatch(expectedHash, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant))
            throw InvalidOutput();

        var path = Path.GetFullPath(
            Path.Combine(extraction, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(
                extraction + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase) ||
            HasReparseAncestor(path, extraction))
            throw InvalidOutput();
        return (identifier, expectedBytes, expectedHash, path);
    }

    private static void ValidateArtifactFile(
        string path,
        string extraction,
        long expectedBytes,
        string expectedHash,
        string identifier,
        List<IDisposable> leases,
        CancellationToken cancellationToken)
    {
        PinnedRecoveryFile? file = PinnedRecoveryFile.Open(path, extraction, 128 * 1024);
        try
        {
            var stream = file.Stream;
            if (stream.Length != expectedBytes) throw InvalidOutput();
            var actualHash = HashStream(stream, cancellationToken);
            file.EnsureIdentity();
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(actualHash), Encoding.ASCII.GetBytes(expectedHash)))
                throw InvalidOutput();
            if (identifier is "markdown_report" or "html_report")
            {
                leases.Add(file);
                file = null;
            }
        }
        finally
        {
            file?.Dispose();
        }
    }
}
