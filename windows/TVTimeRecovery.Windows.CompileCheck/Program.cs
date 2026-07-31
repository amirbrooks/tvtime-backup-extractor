using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TVTimeRecovery.Windows;

internal static class CompileCheckProgram
{
    private static readonly UTF8Encoding Utf8WithoutBom = new(false, true);
    public static int Main()
    {
        var temporaryRoot = Path.Combine(
            Path.GetTempPath(), $"tvtime-windows-validator-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryRoot);
        try
        {
            var output = CreateValidOutput(temporaryRoot);
            using (var accepted = RecoveryOutputValidator.ValidateCompletedOutput(output))
            {
                Require(File.Exists(accepted.MarkdownReport));
                Require(File.Exists(accepted.HtmlReport));
            }

            var rejected = 0;
            var analysis = Path.Combine(output, "TVTime-Extraction", "analysis");
            var marker = Path.Combine(analysis, "recovery_state.json");
            var canonicalMarker = File.ReadAllText(marker, Encoding.UTF8);

            var extra = Path.Combine(analysis, "synthetic-extra.txt");
            File.WriteAllText(extra, "synthetic", Utf8WithoutBom);
            rejected += Rejects(output) ? 1 : 0;
            File.Delete(extra);

            var markdown = Path.Combine(analysis, "TVTime-Recovered-Data.md");
            var canonicalMarkdown = File.ReadAllBytes(markdown);
            File.AppendAllText(markdown, "tampered", Utf8WithoutBom);
            rejected += Rejects(output) ? 1 : 0;
            File.WriteAllBytes(markdown, canonicalMarkdown);

            File.WriteAllText(
                marker,
                canonicalMarker.Replace(
                    "\"status\": \"complete\",",
                    "\"status\": \"complete\",\n  \"status\": \"complete\","),
                Utf8WithoutBom);
            rejected += Rejects(output) ? 1 : 0;
            File.WriteAllText(marker, canonicalMarker, Utf8WithoutBom);

            File.WriteAllText(
                marker,
                canonicalMarker.Replace(
                    "analysis/TVTime-Recovered-Data.html",
                    "analysis/synthetic-wrong-name.html"),
                Utf8WithoutBom);
            rejected += Rejects(output) ? 1 : 0;
            File.WriteAllText(marker, canonicalMarker, Utf8WithoutBom);

            File.WriteAllText(
                marker,
                canonicalMarker.Replace(
                    "\"contract\": \"tvtime-source-snapshot-v0.2\"",
                    "\"contract\": \"synthetic-invalid-contract\""),
                Utf8WithoutBom);
            rejected += Rejects(output) ? 1 : 0;
            File.WriteAllText(marker, canonicalMarker, Utf8WithoutBom);

            File.WriteAllText(
                marker,
                canonicalMarker.Replace("\"files_extracted\": 1", "\"files_extracted\": 2"),
                Utf8WithoutBom);
            rejected += Rejects(output) ? 1 : 0;
            File.WriteAllText(marker, canonicalMarker, Utf8WithoutBom);

            var extraRaw = Path.Combine(
                output, "TVTime-Extraction", "raw", "AppDomain-com.tozelabs.tvshowtime",
                "synthetic-extra.db");
            File.WriteAllText(extraRaw, "synthetic", Utf8WithoutBom);
            rejected += Rejects(output) ? 1 : 0;
            File.Delete(extraRaw);

            Require(rejected == 7);
            Console.WriteLine("Windows output validator: valid output accepted; 7 tamper cases rejected");
            return 0;
        }
        finally
        {
            if (Path.GetFileName(temporaryRoot).StartsWith(
                    "tvtime-windows-validator-", StringComparison.Ordinal))
                Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    private static string CreateValidOutput(string temporaryRoot)
    {
        var output = Path.Combine(temporaryRoot, "output");
        var extraction = Path.Combine(output, "TVTime-Extraction");
        Directory.CreateDirectory(Path.Combine(extraction, "metadata"));
        Directory.CreateDirectory(Path.Combine(extraction, "analysis"));
        Directory.CreateDirectory(Path.Combine(extraction, "manifest"));
        var rawDomain = Path.Combine(extraction, "raw", "AppDomain-com.tozelabs.tvshowtime");
        var rawDocuments = Path.Combine(rawDomain, "Documents");
        Directory.CreateDirectory(rawDocuments);
        var rawPayload = Encoding.UTF8.GetBytes("synthetic-private-database\n");
        var rawHash = Convert.ToHexString(SHA256.HashData(rawPayload)).ToLowerInvariant();
        File.WriteAllBytes(Path.Combine(rawDocuments, "DioCache.db"), rawPayload);
        var inventoryPayload = Encoding.UTF8.GetBytes(
            "file_id,domain,relative_path,declared_size,actual_size,size_match,mtime,sha256\r\n" +
            $"{new string('0', 40)},AppDomain-com.tozelabs.tvshowtime,Documents/DioCache.db," +
            $"{rawPayload.Length},{rawPayload.Length},True,,{rawHash}\r\n");

        var bindings = new List<Dictionary<string, object>>();
        foreach (var (identifier, relativePath) in RecoveryArtifactContract.RequiredArtifacts)
        {
            var path = Path.Combine(
                extraction, relativePath.Replace('/', Path.DirectorySeparatorChar));
            var payload = identifier == "extraction_inventory"
                ? inventoryPayload
                : Encoding.UTF8.GetBytes($"synthetic:{identifier}\n");
            File.WriteAllBytes(path, payload);
            bindings.Add(new Dictionary<string, object>
            {
                ["id"] = identifier,
                ["relative_path"] = relativePath,
                ["bytes"] = payload.Length,
                ["sha256"] = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(),
            });
        }

        var state = new Dictionary<string, object?>
        {
            ["schema_version"] = 2,
            ["contract"] = "tvtime-recovery-state-v0.2",
            ["status"] = "complete",
            ["completed_utc"] = "2000-01-01T00:00:00+00:00",
            ["pdf"] = new Dictionary<string, object?>
            {
                ["status"] = "omitted",
                ["artifact_id"] = null,
            },
            ["source_snapshot"] = new Dictionary<string, object>
            {
                ["contract"] = "tvtime-source-snapshot-v0.2",
                ["inventory"] = new Dictionary<string, object>
                {
                    ["bytes"] = bindings.Single(item =>
                        (string)item["id"] == "extraction_inventory")["bytes"],
                    ["sha256"] = bindings.Single(item =>
                        (string)item["id"] == "extraction_inventory")["sha256"],
                },
                ["raw_tree"] = new Dictionary<string, object>
                {
                    ["files"] = 1,
                    ["bytes"] = rawPayload.Length,
                    ["sha256"] = RawTreeDigest(rawPayload.Length, rawHash),
                },
            },
            ["aggregates"] = new Dictionary<string, object>
            {
                ["extraction"] = new Dictionary<string, object>
                {
                    ["files_expected"] = 1,
                    ["files_extracted"] = 1,
                    ["bytes_extracted"] = rawPayload.Length,
                    ["selected_declared_bytes"] = rawPayload.Length,
                    ["size_discrepancy_count"] = 0,
                },
                ["analysis"] = new Dictionary<string, object>
                {
                    ["series_library"] = 0,
                    ["watched_movies"] = 0,
                    ["movie_watchlist"] = 0,
                    ["favorite_shows"] = 0,
                    ["favorite_movies"] = 0,
                    ["watch_events"] = 0,
                    ["watch_events_with_titles"] = 0,
                    ["episode_cache_unique"] = 0,
                    ["parser_status"] = "empty",
                },
                ["report"] = new Dictionary<string, object>
                {
                    ["image_cache_references"] = 0,
                    ["trailer_references"] = 0,
                    ["media_urls"] = 0,
                    ["pdf_status"] = "omitted",
                    ["pdf_omission_reason"] = "Synthetic renderer omission.",
                },
            },
            ["artifacts"] = bindings,
        };
        File.WriteAllText(
            Path.Combine(extraction, "analysis", "recovery_state.json"),
            JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }),
            Utf8WithoutBom);
        return output;
    }

    private static string RawTreeDigest(int byteSize, string rawHash)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("tvtime-raw-tree-digest-v0.2\0"u8);
        var path = Encoding.UTF8.GetBytes(
            "AppDomain-com.tozelabs.tvshowtime/Documents/DioCache.db");
        Span<byte> size = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(size, (ulong)path.Length);
        digest.AppendData(size);
        digest.AppendData(path);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(size, (ulong)byteSize);
        digest.AppendData(size);
        digest.AppendData(Convert.FromHexString(rawHash));
        return Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
    }

    private static bool Rejects(string output)
    {
        try
        {
            using var accepted = RecoveryOutputValidator.ValidateCompletedOutput(output);
            return false;
        }
        catch
        {
            return true;
        }
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("A synthetic validator check failed.");
    }
}
