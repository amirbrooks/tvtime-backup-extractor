using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace TVTimeRecovery.Windows;

internal readonly record struct DestinationIdentity(ulong Device, ulong Inode);

internal sealed class NativeHelperProcess : IAsyncDisposable
{
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint HandleFlagInherit = 0x00000001;
    private const nuint ProcThreadAttributeHandleList = 0x00020002;
    private const uint GenericWrite = 0x40000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileAddSubdirectory = 0x00000004;
    private const uint FileTraverse = 0x00000020;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;

    private readonly SafeFileHandle _process;
    private readonly SafeFileHandle _job;
    private readonly FileStream _control;
    private readonly FileStream _secret;
    private readonly StreamReader _events;
    private int _disposed;

    public DestinationIdentity DestinationIdentity { get; }

    private NativeHelperProcess(
        SafeFileHandle process,
        SafeFileHandle job,
        FileStream control,
        FileStream secret,
        StreamReader events,
        DestinationIdentity destinationIdentity)
    {
        _process = process;
        _job = job;
        _control = control;
        _secret = secret;
        _events = events;
        DestinationIdentity = destinationIdentity;
    }

    public static NativeHelperProcess Start(string executable, string destinationParent)
    {
        SafeFileHandle? controlRead = null;
        SafeFileHandle? controlWrite = null;
        SafeFileHandle? outputRead = null;
        SafeFileHandle? outputWrite = null;
        SafeFileHandle? secretRead = null;
        SafeFileHandle? secretWrite = null;
        SafeFileHandle? destination = null;
        SafeFileHandle? nullHandle = null;
        SafeFileHandle? process = null;
        SafeFileHandle? job = null;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        try
        {
            CreateAnonymousPipe(out controlRead, out controlWrite, childReads: true);
            CreateAnonymousPipe(out outputRead, out outputWrite, childReads: false);
            CreateAnonymousPipe(out secretRead, out secretWrite, childReads: true);
            destination = CreateFileW(
                destinationParent,
                FileReadAttributes | FileAddSubdirectory | FileTraverse,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            EnsureHandle(destination, "destination");
            SetInheritable(destination, true);
            var destinationIdentity = Identity(destination);
            nullHandle = CreateFileW("NUL", GenericWrite, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            EnsureHandle(nullHandle, "null output");
            SetInheritable(nullHandle, true);

            var handles = new[]
            {
                controlRead.DangerousGetHandle(), outputWrite.DangerousGetHandle(),
                secretRead.DangerousGetHandle(), destination.DangerousGetHandle(),
                nullHandle.DangerousGetHandle(),
            };
            handleList = Marshal.AllocHGlobal(IntPtr.Size * handles.Length);
            Marshal.Copy(handles, 0, handleList, handles.Length);

            nuint attributeSize = 0;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeSize);
            attributeList = Marshal.AllocHGlobal((nint)attributeSize);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeSize) ||
                !UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    ProcThreadAttributeHandleList,
                    handleList,
                    (nuint)(IntPtr.Size * handles.Length),
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw new Win32Exception();
            }

            var startup = new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Size = (uint)Marshal.SizeOf<StartupInfoEx>(),
                    Flags = StartfUseStdHandles,
                    StandardInput = controlRead.DangerousGetHandle(),
                    StandardOutput = outputWrite.DangerousGetHandle(),
                    StandardError = nullHandle.DangerousGetHandle(),
                },
                AttributeList = attributeList,
            };
            environment = BuildEnvironment(
                secretRead.DangerousGetHandle(),
                destination.DangerousGetHandle());
            var commandLine = new StringBuilder($"\"{executable}\"");
            if (!CreateProcessW(
                executable,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                ExtendedStartupInfoPresent | CreateNoWindow | CreateSuspended | CreateUnicodeEnvironment,
                environment,
                Path.GetDirectoryName(executable),
                ref startup,
                out var processInformation))
            {
                throw new Win32Exception();
            }
            using var thread = new SafeFileHandle(processInformation.Thread, ownsHandle: true);
            process = new SafeFileHandle(processInformation.Process, ownsHandle: true);
            job = CreateJobObjectW(IntPtr.Zero, null);
            EnsureHandle(job, "job");
            ConfigureKillOnClose(job);
            if (!AssignProcessToJobObject(job, process))
            {
                TerminateProcess(process, 1);
                throw new Win32Exception();
            }
            if (ResumeThread(thread) == uint.MaxValue) throw new Win32Exception();

            controlRead.Dispose();
            controlRead = null;
            outputWrite.Dispose();
            outputWrite = null;
            secretRead.Dispose();
            secretRead = null;
            destination.Dispose();
            destination = null;
            nullHandle.Dispose();
            nullHandle = null;

            var control = new FileStream(controlWrite!, FileAccess.Write, 4096, isAsync: true);
            controlWrite = null;
            var secret = new FileStream(secretWrite!, FileAccess.Write, 4096, isAsync: true);
            secretWrite = null;
            var output = new FileStream(outputRead!, FileAccess.Read, 4096, isAsync: true);
            outputRead = null;
            var reader = new StreamReader(output, new UTF8Encoding(false, true), false, 4096, leaveOpen: false);
            var result = new NativeHelperProcess(
                process, job, control, secret, reader, destinationIdentity);
            process = null;
            job = null;
            return result;
        }
        finally
        {
            controlRead?.Dispose();
            controlWrite?.Dispose();
            outputRead?.Dispose();
            outputWrite?.Dispose();
            secretRead?.Dispose();
            secretWrite?.Dispose();
            destination?.Dispose();
            nullHandle?.Dispose();
            if (process is not null && !process.IsInvalid && !process.IsClosed)
            {
                // Until ownership is transferred to the returned instance, any
                // startup failure must kill the child, including failures before
                // the kill-on-close Job Object is configured or attached.
                _ = TerminateProcess(process, 1);
            }
            job?.Dispose();
            process?.Dispose();
            if (attributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
        }
    }

    public async Task SendControlAsync(byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length is <= 0 or > 1_048_576) throw new InvalidDataException();
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)payload.Length);
        await _control.WriteAsync(header, cancellationToken);
        await _control.WriteAsync(payload, cancellationToken);
        await _control.FlushAsync(cancellationToken);
    }

    public async Task SendSecretAsync(string password, CancellationToken cancellationToken)
    {
        var payload = Encoding.UTF8.GetBytes(password);
        try
        {
            if (payload.Length is <= 0 or > 16_384) throw new InvalidDataException();
            var header = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(header, (uint)payload.Length);
            await _secret.WriteAsync(header, cancellationToken);
            await _secret.WriteAsync(payload, cancellationToken);
            await _secret.FlushAsync(cancellationToken);
            _secret.Dispose();
        }
        finally
        {
            Array.Clear(payload);
        }
    }

    public async IAsyncEnumerable<JsonDocument> EventsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        while (true)
        {
            var line = await ReadBoundedLineAsync(cancellationToken);
            if (line is null) yield break;
            yield return JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 32 });
        }
    }

    public async Task CancelAsync()
    {
        if (Volatile.Read(ref _disposed) != 0) return;
        var payload = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["protocolVersion"] = 3,
            ["type"] = "cancel",
        });
        try { await SendControlAsync(payload, CancellationToken.None); }
        catch (Exception) { }
    }

    private async Task<string?> ReadBoundedLineAsync(CancellationToken cancellationToken)
    {
        const int maximumBytes = 1_048_576;
        const int maximumCharacters = maximumBytes / 4;
        var line = new StringBuilder();
        var one = new char[1];
        while (true)
        {
            var read = await _events.ReadAsync(one.AsMemory(), cancellationToken);
            if (read == 0) return line.Length == 0 ? null : throw new InvalidDataException();
            if (one[0] == '\n') return line.ToString();
            if (one[0] == '\r') continue;
            line.Append(one[0]);
            if (line.Length > maximumCharacters) throw new InvalidDataException();
        }
    }

    public async Task WaitForSuccessfulExitAsync()
    {
        var waitResult = await Task.Run(() => WaitForSingleObject(_process, 5_000));
        if (waitResult == WaitTimeout)
            throw new TimeoutException("The private recovery helper did not exit after completion.");
        if (waitResult != WaitObject0 || !GetExitCodeProcess(_process, out var exitCode))
            throw new Win32Exception();
        if (exitCode != 0)
            throw new InvalidDataException("The private recovery helper exited unsuccessfully.");
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _control.Dispose();
        _secret.Dispose();
        var waitResult = await Task.Run(() => WaitForSingleObject(_process, 5_000));
        _job.Dispose();
        if (waitResult == WaitTimeout)
        {
            _ = await Task.Run(() => WaitForSingleObject(_process, 5_000));
        }
        _events.Dispose();
        _process.Dispose();
    }

    private static void CreateAnonymousPipe(
        out SafeFileHandle read,
        out SafeFileHandle write,
        bool childReads)
    {
        var security = new SecurityAttributes
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            InheritHandle = true,
        };
        if (!CreatePipe(out read, out write, ref security, 0)) throw new Win32Exception();
        SetInheritable(childReads ? write : read, false);
    }

    private static void SetInheritable(SafeFileHandle handle, bool inherited)
    {
        if (!SetHandleInformation(handle, HandleFlagInherit, inherited ? HandleFlagInherit : 0))
            throw new Win32Exception();
    }

    private static void EnsureHandle(SafeFileHandle? handle, string label)
    {
        if (handle is null || handle.IsInvalid) throw new Win32Exception($"Invalid {label} handle");
    }

    private static DestinationIdentity Identity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var info)) throw new Win32Exception();
        const uint Directory = 0x10;
        const uint Reparse = 0x400;
        if ((info.FileAttributes & Directory) == 0 || (info.FileAttributes & Reparse) != 0)
            throw new Win32Exception();
        return new DestinationIdentity(
            info.VolumeSerialNumber,
            ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
    }

    private static IntPtr BuildEnvironment(IntPtr secret, IntPtr destination)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in new[] { "SystemRoot", "WINDIR", "TEMP", "TMP" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrEmpty(value)) values[name] = value;
        }
        values["TVTIME_SECRET_HANDLE"] = secret.ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture);
        values["TVTIME_DESTINATION_HANDLE"] = destination.ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var block = string.Join('\0', values.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => $"{pair.Key}={pair.Value}")) + "\0\0";
        return Marshal.StringToHGlobalUni(block);
    }

    private static void ConfigureKillOnClose(SafeFileHandle job)
    {
        var info = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose,
            },
        };
        var size = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        var pointer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, pointer, false);
            if (!SetInformationJobObject(
                    job, JobObjectExtendedLimitInformationClass, pointer, (uint)size))
                throw new Win32Exception();
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { public int Length; public IntPtr SecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo { public uint Size; public string? Reserved; public string? Desktop; public string? Title; public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags; public ushort ShowWindow, Reserved2; public IntPtr ReservedPointer, StandardInput, StandardOutput, StandardError; }
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx { public StartupInfo StartupInfo; public IntPtr AttributeList; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low, High; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation { public uint FileAttributes; public FileTime CreationTime, LastAccessTime, LastWriteTime; public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow; }
    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public nuint MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public nuint Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation { public JobObjectBasicLimitInformation BasicLimitInformation; public IoCounters IoInfo; public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }

    [DllImport("kernel32", SetLastError = true)] private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32", SetLastError = true)] private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32", SetLastError = true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);
    [DllImport("kernel32", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref nuint size);
    [DllImport("kernel32", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, nuint attribute, IntPtr value, nuint size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string? currentDirectory, ref StartupInfoEx startup, out ProcessInformation process);
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, uint informationClass, IntPtr information, uint length);
    [DllImport("kernel32", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, SafeFileHandle process);
    [DllImport("kernel32", SetLastError = true)] private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
    [DllImport("kernel32", SetLastError = true)] private static extern bool GetExitCodeProcess(SafeFileHandle process, out uint exitCode);
    [DllImport("kernel32", SetLastError = true)] private static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32")] private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
}
