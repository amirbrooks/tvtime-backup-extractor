using System.Diagnostics;
using System.Text.Json;
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
    private const int ProtocolVersion = 3;

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
        return await Task.Run(
            () => RecoveryOutputValidator.ValidateCompletedOutput(output, cancellationToken),
            cancellationToken);
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
}
