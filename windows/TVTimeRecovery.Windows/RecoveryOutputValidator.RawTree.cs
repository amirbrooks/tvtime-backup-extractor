using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TVTimeRecovery.Windows;

internal static partial class RecoveryOutputValidator
{
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

    private sealed record InventoryEntry(string RelativeRawPath, long ActualSize, string Sha256);

    private static void ValidateSealedRawTree(
        string extraction,
        long expectedInventoryBytes,
        string expectedInventoryHash,
        long expectedFileCount,
        long expectedRawBytes,
        string expectedTreeHash,
        CancellationToken cancellationToken)
    {
        var inventoryPath = Path.Combine(extraction, "metadata", "inventory.csv");
        var inventoryPayload = ReadStableRegularFile(
            inventoryPath,
            extraction,
            expectedInventoryBytes,
            expectedInventoryHash,
            capture: true,
            cancellationToken: cancellationToken);
        var entries = ParseInventory(inventoryPayload, cancellationToken);
        long actualBytes = 0;
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { actualBytes = checked(actualBytes + entry.ActualSize); }
            catch (OverflowException) { throw InvalidOutput(); }
        }
        if (entries.Count != expectedFileCount || actualBytes != expectedRawBytes ||
            CanonicalTreeDigest(entries, cancellationToken) != expectedTreeHash)
            throw InvalidOutput();

        var rawRoot = Path.Combine(extraction, "raw");
        ValidateRawTreePass(rawRoot, entries, cancellationToken);
        ValidateRawTreePass(rawRoot, entries, cancellationToken);
        _ = ReadStableRegularFile(
            inventoryPath,
            extraction,
            expectedInventoryBytes,
            expectedInventoryHash,
            capture: false,
            cancellationToken: cancellationToken);
    }

    private static byte[] ReadStableRegularFile(
        string path,
        string root,
        long expectedBytes,
        string expectedHash,
        bool capture,
        CancellationToken cancellationToken)
    {
        if (expectedBytes is <= 0 or > RecoveryArtifactContract.MaximumInventoryBytes)
            throw InvalidOutput();
        using var file = PinnedRecoveryFile.Open(path, root, 128 * 1024);
        var stream = file.Stream;
        if (stream.Length != expectedBytes) throw InvalidOutput();
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var captured = capture ? new MemoryStream(checked((int)expectedBytes)) : null;
        var buffer = new byte[128 * 1024];
        long observed = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = stream.Read(buffer, 0, buffer.Length);
            if (count == 0) break;
            observed = checked(observed + count);
            digest.AppendData(buffer, 0, count);
            captured?.Write(buffer, 0, count);
        }
        var observedHash = Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
        file.EnsureIdentity();
        if (observed != expectedBytes || stream.Length != expectedBytes ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(observedHash), Encoding.ASCII.GetBytes(expectedHash)))
            throw InvalidOutput();
        return captured?.ToArray() ?? Array.Empty<byte>();
    }

    private static List<InventoryEntry> ParseInventory(
        byte[] payload,
        CancellationToken cancellationToken)
    {
        string text;
        try { text = new UTF8Encoding(false, true).GetString(payload); }
        catch (DecoderFallbackException) { throw InvalidOutput(); }
        var rows = ParseCsv(text, cancellationToken);
        if (rows.Count == 0 || !rows[0].SequenceEqual(InventoryFields, StringComparer.Ordinal) ||
            rows.Count - 1 > MaximumRawTreeEntries)
            throw InvalidOutput();
        var entries = new List<InventoryEntry>(rows.Count - 1);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows.Skip(1))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = CanonicalInventoryRelativePath(row.Count == InventoryFields.Length
                ? row[2]
                : string.Empty);
            if (row.Count != InventoryFields.Length ||
                !Regex.IsMatch(row[0], "^[0-9a-f]{40}$", RegexOptions.CultureInvariant) ||
                !IsPortableComponent(row[1]) || relativePath is null ||
                !TryCanonicalNonnegativeInteger(row[3], out var declaredSize) ||
                !TryCanonicalNonnegativeInteger(row[4], out var actualSize) ||
                row[5] != (declaredSize == actualSize ? "True" : "False") ||
                !Regex.IsMatch(row[7], "^[0-9a-f]{64}$", RegexOptions.CultureInvariant))
                throw InvalidOutput();
            var rawPath = $"{row[1]}/{relativePath}";
            if (!paths.Add(rawPath)) throw InvalidOutput();
            entries.Add(new InventoryEntry(rawPath, actualSize, row[7]));
        }
        entries.Sort(static (left, right) => CompareUtf8(left.RelativeRawPath, right.RelativeRawPath));
        return entries;
    }

    private static string? CanonicalInventoryRelativePath(string value)
    {
        const string escapePrefix = "./";
        var escaped = value.StartsWith(escapePrefix, StringComparison.Ordinal);
        var candidate = escaped ? value[escapePrefix.Length..] : value;
        var requiresEscape = candidate.Length > 0 && "=+-@\t\r\n".Contains(candidate[0]);
        // v0.2 inventories stored formula-leading paths verbatim. Their bytes are
        // bound by the completed recovery marker, so accept that legacy read form
        // while keeping the explicit escape mandatory when it is present.
        if ((escaped && !requiresEscape) || string.IsNullOrEmpty(candidate) ||
            candidate.Contains('\\') || candidate.StartsWith('/') || candidate.EndsWith('/') ||
            candidate.Split('/').Any(part => !IsPortableComponent(part)))
            return null;
        return candidate;
    }

    private static List<List<string>> ParseCsv(
        string text,
        CancellationToken cancellationToken)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        var afterQuote = false;
        var fieldStarted = false;
        for (var index = 0; index < text.Length; index++)
        {
            if ((index & 4095) == 0) cancellationToken.ThrowIfCancellationRequested();
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

    private static string CanonicalTreeDigest(
        IEnumerable<InventoryEntry> entries,
        CancellationToken cancellationToken)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("tvtime-raw-tree-digest-v0.2\0"u8);
        Span<byte> size = stackalloc byte[8];
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
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

    private static void ValidateRawTreePass(
        string rawRoot,
        IReadOnlyList<InventoryEntry> entries,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(rawRoot) || IsReparse(rawRoot)) throw InvalidOutput();
        var expectedFiles = entries.ToDictionary(
            entry => entry.RelativeRawPath, entry => entry, StringComparer.OrdinalIgnoreCase);
        if (expectedFiles.Count != entries.Count) throw InvalidOutput();
        var expectedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
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
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var member in Directory.GetFileSystemEntries(pending.Pop()))
            {
                cancellationToken.ThrowIfCancellationRequested();
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
                    _ = ReadRawFile(
                        member,
                        rawRoot,
                        expected.ActualSize,
                        expected.Sha256,
                        cancellationToken);
                }
                else throw InvalidOutput();
            }
        }
        if (!observedFiles.SetEquals(expectedFiles.Keys) ||
            !observedDirectories.SetEquals(expectedDirectories))
            throw InvalidOutput();
    }

    private static bool ReadRawFile(
        string path,
        string rawRoot,
        long expectedBytes,
        string expectedHash,
        CancellationToken cancellationToken)
    {
        // Raw files are user-selected source data. Their sealed inventory size is
        // the validation bound; generated-artifact product limits do not apply.
        using var file = PinnedRecoveryFile.Open(path, rawRoot, 128 * 1024);
        var stream = file.Stream;
        if (stream.Length != expectedBytes) throw InvalidOutput();
        var observedHash = HashStream(stream, cancellationToken);
        file.EnsureIdentity();
        if (stream.Length != expectedBytes ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(observedHash), Encoding.ASCII.GetBytes(expectedHash)))
            throw InvalidOutput();
        return true;
    }
}
