using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Security;
using AssessmentTool.Windows.Components;
using Microsoft.Win32.SafeHandles;

namespace AssessmentTool.Windows.Processes;

[Flags]
internal enum WindowsProcessCreationFlags : uint
{
    CreateSuspended = 0x00000004,
    ExtendedStartupInfoPresent = 0x00080000,
    CreateNoWindow = 0x08000000
}

internal enum ProcessPipeKind
{
    StandardInput,
    StandardOutput,
    StandardError
}

internal interface IWindowsProcess : IDisposable
{
}

internal interface IWindowsJob : IDisposable
{
}

internal interface IWindowsStartupAttributeList : IDisposable
{
}

internal interface IWindowsProcessApi
{
    WindowsProcessPipe CreatePipe(ProcessPipeKind kind);

    IWindowsJob CreateKillOnCloseJob();

    IWindowsStartupAttributeList CreateStartupAttributeList(IReadOnlyList<IntPtr> inheritedHandles);

    IWindowsProcess CreateProcess(
        string applicationName,
        string commandLine,
        WindowsProcessCreationFlags creationFlags,
        WindowsProcessPipe standardInput,
        WindowsProcessPipe standardOutput,
        WindowsProcessPipe standardError,
        IWindowsStartupAttributeList startupAttributes);

    void AssignProcessToJob(IWindowsJob job, IWindowsProcess process);

    void ResumePrimaryThread(IWindowsProcess process);

    Task WaitForExitAsync(IWindowsProcess process);

    int GetExitCode(IWindowsProcess process);

    void TerminateProcess(IWindowsProcess process, uint exitCode);

    void TerminateJob(IWindowsJob job, uint exitCode);
}

internal sealed class WindowsProcessPipe : IDisposable
{
    private bool disposed;

    internal WindowsProcessPipe(ProcessPipeKind kind, SafeFileHandle childHandle, Stream parentStream)
    {
        Kind = kind;
        ChildHandle = childHandle ?? throw new ArgumentNullException(nameof(childHandle));
        ParentStream = parentStream ?? throw new ArgumentNullException(nameof(parentStream));
    }

    internal ProcessPipeKind Kind { get; }
    internal SafeFileHandle ChildHandle { get; }
    internal Stream ParentStream { get; }

    internal void CloseChildHandle()
    {
        ChildHandle.Dispose();
    }

    internal void CloseParentStream()
    {
        ParentStream.Dispose();
    }

    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;
            ParentStream.Dispose();
            ChildHandle.Dispose();
        }
    }
}

internal sealed class WindowsProcessNativeException : Exception
{
    internal WindowsProcessNativeException(ProcessFailureStage stage, int nativeErrorCode)
        : base("Windows 受控进程 API 调用失败。")
    {
        Stage = stage;
        NativeErrorCode = nativeErrorCode;
    }

    internal ProcessFailureStage Stage { get; }
    internal int NativeErrorCode { get; }
}

internal sealed class WindowsProcessRunner : IProcessRunner
{
    private const uint ControlledTerminationExitCode = 0xE0000001;
    private static readonly TimeSpan DefaultTerminationObservationTimeout = TimeSpan.FromSeconds(2);
    private static readonly WindowsProcessCreationFlags RequiredCreationFlags =
        WindowsProcessCreationFlags.CreateSuspended
        | WindowsProcessCreationFlags.CreateNoWindow
        | WindowsProcessCreationFlags.ExtendedStartupInfoPresent;

    private readonly IWindowsProcessApi processApi;
    private readonly CommandSafetyPolicy safetyPolicy;
    private readonly TimeSpan terminationObservationTimeout;

    internal WindowsProcessRunner()
        : this(new NativeWindowsProcessApi(), new CommandSafetyPolicy(), DefaultTerminationObservationTimeout)
    {
    }

    internal WindowsProcessRunner(IWindowsProcessApi processApi)
        : this(processApi, new CommandSafetyPolicy(), DefaultTerminationObservationTimeout)
    {
    }

    internal WindowsProcessRunner(IWindowsProcessApi processApi, TimeSpan terminationObservationTimeout)
        : this(processApi, new CommandSafetyPolicy(), terminationObservationTimeout)
    {
    }

    internal WindowsProcessRunner(IWindowsProcessApi processApi, CommandSafetyPolicy safetyPolicy)
        : this(processApi, safetyPolicy, DefaultTerminationObservationTimeout)
    {
    }

    internal WindowsProcessRunner(
        IWindowsProcessApi processApi,
        CommandSafetyPolicy safetyPolicy,
        TimeSpan terminationObservationTimeout)
    {
        this.processApi = processApi ?? throw new ArgumentNullException(nameof(processApi));
        this.safetyPolicy = safetyPolicy ?? throw new ArgumentNullException(nameof(safetyPolicy));
        if (terminationObservationTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(terminationObservationTimeout),
                terminationObservationTimeout,
                "终止后的观察时间必须大于零。");
        }

        this.terminationObservationTimeout = terminationObservationTimeout;
    }

    public async Task<ProcessRunResult> RunAsync(
        ComponentExecutionCandidate executable,
        ProcessRunRequest request,
        CancellationToken cancellationToken)
    {
        if (executable == null)
        {
            throw new ArgumentNullException(nameof(executable));
        }

        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var safetyDecision = safetyPolicy.Validate(request.Command);
        if (!safetyDecision.Allowed)
        {
            return ProcessRunResult.Rejected(safetyDecision.Code);
        }

        var validatedCommandText = request.Command.CommandText.Trim();

        if (cancellationToken.IsCancellationRequested)
        {
            return ProcessRunResult.Stopped(
                ProcessRunOutcome.Cancelled,
                Array.Empty<byte>(),
                Array.Empty<byte>());
        }

        if (request.Command.Timeout <= TimeSpan.Zero)
        {
            return ProcessRunResult.Failed(
                ProcessFailureStage.ProcessWait,
                "invalid-timeout",
                null);
        }

        WindowsProcessPipe? standardInput = null;
        WindowsProcessPipe? standardOutput = null;
        WindowsProcessPipe? standardError = null;
        IWindowsJob? job = null;
        IWindowsStartupAttributeList? startupAttributes = null;
        IWindowsProcess? process = null;
        ProcessRunResult? launchFailure = null;

        try
        {
            executable.LaunchWhileLocked(applicationName =>
            {
                try
                {
                    if (!IsTrustedApplicationName(applicationName))
                    {
                        launchFailure = ProcessRunResult.Failed(
                            ProcessFailureStage.ProcessCreation,
                            "invalid-application-name",
                            null);
                        return;
                    }

                    if (IsPlinkExecutableCandidate(executable.ComponentId, applicationName) &&
                        !request.HasControlledPlinkPlan())
                    {
                        launchFailure = ProcessRunResult.Rejected("plink-plan-required");
                        return;
                    }

                    var serializedArguments = WindowsArgumentSerializer.Serialize(request.ArgumentTokens);
                    var trustedArgv0 = QuoteTrustedApplicationName(applicationName);
                    var commandLine = serializedArguments.Length == 0
                        ? trustedArgv0
                        : trustedArgv0 + " " + serializedArguments;

                    standardInput = processApi.CreatePipe(ProcessPipeKind.StandardInput);
                    standardOutput = processApi.CreatePipe(ProcessPipeKind.StandardOutput);
                    standardError = processApi.CreatePipe(ProcessPipeKind.StandardError);
                    job = processApi.CreateKillOnCloseJob();
                    startupAttributes = processApi.CreateStartupAttributeList(
                        new[]
                        {
                            standardInput.ChildHandle.DangerousGetHandle(),
                            standardOutput.ChildHandle.DangerousGetHandle(),
                            standardError.ChildHandle.DangerousGetHandle()
                        });
                    process = processApi.CreateProcess(
                        applicationName,
                        commandLine,
                        RequiredCreationFlags,
                        standardInput,
                        standardOutput,
                        standardError,
                        startupAttributes);

                    standardInput.CloseChildHandle();
                    standardOutput.CloseChildHandle();
                    standardError.CloseChildHandle();

                    try
                    {
                        processApi.AssignProcessToJob(job, process);
                    }
                    catch (WindowsProcessNativeException)
                    {
                        var terminationFailure = TryTerminateSuspendedProcess(process);
                        if (terminationFailure != null)
                        {
                            launchFailure = ProcessRunResult.Failed(
                                ProcessFailureStage.ProcessTermination,
                                NativeFailureCode(ProcessFailureStage.ProcessTermination),
                                terminationFailure.NativeErrorCode);
                            return;
                        }

                        throw;
                    }

                    try
                    {
                        processApi.ResumePrimaryThread(process);
                    }
                    catch (WindowsProcessNativeException)
                    {
                        var terminationFailure = TryTerminateRunningJob(job);
                        if (terminationFailure != null)
                        {
                            launchFailure = ProcessRunResult.Failed(
                                ProcessFailureStage.ProcessTermination,
                                NativeFailureCode(ProcessFailureStage.ProcessTermination),
                                terminationFailure.NativeErrorCode);
                            return;
                        }

                        throw;
                    }
                }
                catch (WindowsProcessNativeException error)
                {
                    launchFailure = ProcessRunResult.Failed(
                        error.Stage,
                        NativeFailureCode(error.Stage),
                        error.NativeErrorCode);
                }
                catch (ArgumentException)
                {
                    launchFailure = ProcessRunResult.Failed(
                        ProcessFailureStage.ProcessCreation,
                        "invalid-argument-token",
                        null);
                }
                catch
                {
                    launchFailure = ProcessRunResult.Failed(
                        ProcessFailureStage.ProcessCreation,
                        "process-creation-failed",
                        null);
                }
            });

            if (launchFailure != null)
            {
                return launchFailure;
            }

            if (standardInput == null
                || standardOutput == null
                || standardError == null
                || job == null
                || process == null)
            {
                return ProcessRunResult.Failed(
                    ProcessFailureStage.ProcessCreation,
                    "launch-state-invalid",
                    null);
            }

            var stdoutTask = ReadAllBytesAsync(standardOutput.ParentStream);
            var stderrTask = ReadAllBytesAsync(standardError.ParentStream);
            var inputCancellation = new CancellationTokenSource();
            var stdinTask = WriteCommandAndCloseAsync(
                standardInput,
                request.InputEncoding.GetBytes(validatedCommandText + "\r\n"),
                inputCancellation.Token);
            var waitTask = processApi.WaitForExitAsync(process);
            var timeoutCancellation = new CancellationTokenSource();

            try
            {
                var cancellationSignal = Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                var timeoutSignal = Task.Delay(request.Command.Timeout, timeoutCancellation.Token);
                var completed = await Task.WhenAny(waitTask, stdinTask, cancellationSignal, timeoutSignal);

                if (completed == stdinTask)
                {
                    try
                    {
                        await stdinTask;
                    }
                    catch
                    {
                        var terminationFailure = TryTerminateRunningJob(job);
                        await ObserveWithinAsync(waitTask, terminationObservationTimeout);
                        var failedOutput = await ReadOutputsWithinAsync(
                            stdoutTask,
                            stderrTask,
                            terminationObservationTimeout);
                        if (terminationFailure != null)
                        {
                            return ProcessRunResult.Failed(
                                ProcessFailureStage.ProcessTermination,
                                NativeFailureCode(ProcessFailureStage.ProcessTermination),
                                terminationFailure.NativeErrorCode,
                                failedOutput.StandardOutput,
                                failedOutput.StandardError);
                        }

                        return ProcessRunResult.Failed(
                            ProcessFailureStage.StandardInput,
                            "stdin-write-failed",
                            null,
                            failedOutput.StandardOutput,
                            failedOutput.StandardError);
                    }

                    completed = await Task.WhenAny(waitTask, cancellationSignal, timeoutSignal);
                }

                if (completed == cancellationSignal || completed == timeoutSignal)
                {
                    var outcome = completed == cancellationSignal
                        ? ProcessRunOutcome.Cancelled
                        : ProcessRunOutcome.TimedOut;
                    inputCancellation.Cancel();
                    standardInput.CloseParentStream();
                    var terminationFailure = TryTerminateRunningJob(job);
                    await ObserveWithinAsync(stdinTask, terminationObservationTimeout);
                    await ObserveWithinAsync(waitTask, terminationObservationTimeout);
                    var stoppedOutput = await ReadOutputsWithinAsync(
                        stdoutTask,
                        stderrTask,
                        terminationObservationTimeout);
                    if (terminationFailure != null)
                    {
                        return ProcessRunResult.Failed(
                            terminationFailure.Stage,
                            NativeFailureCode(terminationFailure.Stage),
                            terminationFailure.NativeErrorCode,
                            stoppedOutput.StandardOutput,
                            stoppedOutput.StandardError);
                    }

                    return ProcessRunResult.Stopped(
                        outcome,
                        stoppedOutput.StandardOutput,
                        stoppedOutput.StandardError);
                }

                await waitTask;
                try
                {
                    await stdinTask;
                }
                catch
                {
                    var failedOutput = await ReadOutputsWithinAsync(
                        stdoutTask,
                        stderrTask,
                        terminationObservationTimeout);
                    return ProcessRunResult.Failed(
                        ProcessFailureStage.StandardInput,
                        "stdin-write-failed",
                        null,
                        failedOutput.StandardOutput,
                        failedOutput.StandardError);
                }

                ProcessOutputBytes output;
                try
                {
                    output = await ReadOutputsAsync(stdoutTask, stderrTask);
                }
                catch
                {
                    return ProcessRunResult.Failed(
                        ProcessFailureStage.ProcessWait,
                        "output-read-failed",
                        null);
                }

                return ProcessRunResult.Completed(
                    output.StandardOutput,
                    output.StandardError,
                    processApi.GetExitCode(process));
            }
            catch (WindowsProcessNativeException error)
            {
                var terminationFailure = TryTerminateRunningJob(job);
                var output = await ReadOutputsWithinAsync(
                    stdoutTask,
                    stderrTask,
                    terminationObservationTimeout);
                if (terminationFailure != null)
                {
                    return ProcessRunResult.Failed(
                        ProcessFailureStage.ProcessTermination,
                        NativeFailureCode(ProcessFailureStage.ProcessTermination),
                        terminationFailure.NativeErrorCode,
                        output.StandardOutput,
                        output.StandardError);
                }

                return ProcessRunResult.Failed(
                    error.Stage,
                    NativeFailureCode(error.Stage),
                    error.NativeErrorCode,
                    output.StandardOutput,
                    output.StandardError);
            }
            finally
            {
                timeoutCancellation.Cancel();
                timeoutCancellation.Dispose();
                inputCancellation.Dispose();
            }
        }
        catch (ObjectDisposedException)
        {
            return ProcessRunResult.Failed(
                ProcessFailureStage.ProcessCreation,
                "execution-candidate-unavailable",
                null);
        }
        catch (InvalidOperationException)
        {
            return ProcessRunResult.Failed(
                ProcessFailureStage.ProcessCreation,
                "execution-candidate-busy",
                null);
        }
        finally
        {
            standardInput?.Dispose();
            standardOutput?.Dispose();
            standardError?.Dispose();
            process?.Dispose();
            startupAttributes?.Dispose();
            job?.Dispose();
        }
    }

    private static async Task WriteCommandAndCloseAsync(
        WindowsProcessPipe standardInput,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        try
        {
            await standardInput.ParentStream.WriteAsync(bytes, 0, bytes.Length, cancellationToken);
            await standardInput.ParentStream.FlushAsync(cancellationToken);
        }
        finally
        {
            standardInput.CloseParentStream();
        }
    }

    private static async Task<byte[]> ReadAllBytesAsync(Stream stream)
    {
        using (var output = new MemoryStream())
        {
            var buffer = new byte[81920];
            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(
                       buffer,
                       0,
                       buffer.Length,
                       CancellationToken.None)) != 0)
            {
                output.Write(buffer, 0, bytesRead);
            }

            return output.ToArray();
        }
    }

    private static async Task<ProcessOutputBytes> ReadOutputsAsync(
        Task<byte[]> stdoutTask,
        Task<byte[]> stderrTask)
    {
        await Task.WhenAll(stdoutTask, stderrTask);
        return new ProcessOutputBytes(await stdoutTask, await stderrTask);
    }

    private static async Task<ProcessOutputBytes> ReadOutputsSafelyAsync(
        Task<byte[]> stdoutTask,
        Task<byte[]> stderrTask)
    {
        try
        {
            return await ReadOutputsAsync(stdoutTask, stderrTask);
        }
        catch
        {
            return new ProcessOutputBytes(Array.Empty<byte>(), Array.Empty<byte>());
        }
    }

    private static async Task<bool> ObserveWithinAsync(Task task, TimeSpan timeout)
    {
        try
        {
            var completed = await Task.WhenAny(task, Task.Delay(timeout));
            if (completed != task)
            {
                return false;
            }

            await task;
            return true;
        }
        catch
        {
            return true;
        }
    }

    private static async Task<ProcessOutputBytes> ReadOutputsWithinAsync(
        Task<byte[]> stdoutTask,
        Task<byte[]> stderrTask,
        TimeSpan timeout)
    {
        var combined = Task.WhenAll(stdoutTask, stderrTask);
        var completed = await Task.WhenAny(combined, Task.Delay(timeout));
        if (completed != combined)
        {
            return new ProcessOutputBytes(
                CompletedBytesOrEmpty(stdoutTask),
                CompletedBytesOrEmpty(stderrTask));
        }

        return await ReadOutputsSafelyAsync(stdoutTask, stderrTask);
    }

    private static byte[] CompletedBytesOrEmpty(Task<byte[]> task)
    {
        return task.Status == TaskStatus.RanToCompletion
            ? task.Result
            : Array.Empty<byte>();
    }

    private WindowsProcessNativeException? TryTerminateSuspendedProcess(IWindowsProcess process)
    {
        try
        {
            processApi.TerminateProcess(process, ControlledTerminationExitCode);
            return null;
        }
        catch (WindowsProcessNativeException error)
        {
            return error;
        }
    }

    private WindowsProcessNativeException? TryTerminateRunningJob(IWindowsJob job)
    {
        try
        {
            processApi.TerminateJob(job, ControlledTerminationExitCode);
            return null;
        }
        catch (WindowsProcessNativeException error)
        {
            return error;
        }
    }

    private static string NativeFailureCode(ProcessFailureStage stage)
    {
        switch (stage)
        {
            case ProcessFailureStage.PipeCreation:
                return "pipe-creation-failed";
            case ProcessFailureStage.JobCreation:
                return "job-creation-failed";
            case ProcessFailureStage.StartupAttributeConfiguration:
                return "startup-attributes-failed";
            case ProcessFailureStage.ProcessCreation:
                return "process-creation-failed";
            case ProcessFailureStage.JobAssignment:
                return "job-assignment-failed";
            case ProcessFailureStage.ThreadResume:
                return "thread-resume-failed";
            case ProcessFailureStage.ProcessTermination:
                return "process-termination-failed";
            default:
                return "process-wait-failed";
        }
    }

    private static bool IsTrustedApplicationName(string applicationName)
    {
        if (string.IsNullOrWhiteSpace(applicationName)
            || applicationName.IndexOf('"') >= 0
            || applicationName.IndexOf('\0') >= 0
            || applicationName.IndexOf('\r') >= 0
            || applicationName.IndexOf('\n') >= 0)
        {
            return false;
        }

        var driveAbsolute = applicationName.Length >= 3
            && ((applicationName[0] >= 'A' && applicationName[0] <= 'Z')
                || (applicationName[0] >= 'a' && applicationName[0] <= 'z'))
            && applicationName[1] == ':'
            && IsWindowsDirectorySeparator(applicationName[2]);
        var uncAbsolute = applicationName.Length >= 3
            && IsWindowsDirectorySeparator(applicationName[0])
            && IsWindowsDirectorySeparator(applicationName[1])
            && !IsWindowsDirectorySeparator(applicationName[2]);
        return driveAbsolute || uncAbsolute;
    }

    private static bool IsPlinkExecutableCandidate(string componentId, string applicationName)
    {
        if (string.Equals(componentId, "plink", StringComparison.Ordinal))
        {
            return true;
        }

        var separator = Math.Max(
            applicationName.LastIndexOf('\\'),
            applicationName.LastIndexOf('/'));
        var fileName = separator < 0
            ? applicationName
            : applicationName.Substring(separator + 1);
        return string.Equals(fileName, "plink.exe", StringComparison.OrdinalIgnoreCase);
    }

    private static string QuoteTrustedApplicationName(string applicationName)
    {
        return "\"" + applicationName + "\"";
    }

    private static bool IsWindowsDirectorySeparator(char value)
    {
        return value == '\\' || value == '/';
    }

    private sealed class ProcessOutputBytes
    {
        internal ProcessOutputBytes(byte[] standardOutput, byte[] standardError)
        {
            StandardOutput = standardOutput;
            StandardError = standardError;
        }

        internal byte[] StandardOutput { get; }
        internal byte[] StandardError { get; }
    }
}

internal sealed class NativeWindowsProcessApi : IWindowsProcessApi
{
    private const uint HandleFlagInherit = 0x00000001;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private const int Infinite = -1;
    private static readonly IntPtr ProcThreadAttributeHandleList = new IntPtr(0x00020002);

    public WindowsProcessPipe CreatePipe(ProcessPipeKind kind)
    {
        var securityAttributes = new SecurityAttributes
        {
            Length = Marshal.SizeOf(typeof(SecurityAttributes)),
            InheritHandle = true
        };
        if (!NativeMethods.CreatePipe(
                out var readHandle,
                out var writeHandle,
                ref securityAttributes,
                0))
        {
            throw LastError(ProcessFailureStage.PipeCreation);
        }

        SafeFileHandle childHandle;
        SafeFileHandle parentHandle;
        FileAccess parentAccess;
        if (kind == ProcessPipeKind.StandardInput)
        {
            childHandle = readHandle;
            parentHandle = writeHandle;
            parentAccess = FileAccess.Write;
        }
        else
        {
            childHandle = writeHandle;
            parentHandle = readHandle;
            parentAccess = FileAccess.Read;
        }

        try
        {
            if (!NativeMethods.SetHandleInformation(
                    parentHandle,
                    HandleFlagInherit,
                    0))
            {
                throw LastError(ProcessFailureStage.PipeCreation);
            }

            var parentStream = new FileStream(parentHandle, parentAccess, 4096, isAsync: true);
            return new WindowsProcessPipe(kind, childHandle, parentStream);
        }
        catch
        {
            childHandle.Dispose();
            parentHandle.Dispose();
            throw;
        }
    }

    public IWindowsJob CreateKillOnCloseJob()
    {
        var handle = NativeMethods.CreateJobObject(IntPtr.Zero, null);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new WindowsProcessNativeException(ProcessFailureStage.JobCreation, error);
        }

        var information = new JobObjectExtendedLimitInformation();
        information.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        if (!NativeMethods.SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformationClass,
                ref information,
                Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation))))
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new WindowsProcessNativeException(ProcessFailureStage.JobCreation, error);
        }

        return new NativeWindowsJob(handle);
    }

    public IWindowsStartupAttributeList CreateStartupAttributeList(
        IReadOnlyList<IntPtr> inheritedHandles)
    {
        if (inheritedHandles == null || inheritedHandles.Count != 3)
        {
            throw new ArgumentException("受控进程必须且只能继承三个标准流句柄。", nameof(inheritedHandles));
        }

        return new NativeWindowsStartupAttributeList(inheritedHandles);
    }

    public IWindowsProcess CreateProcess(
        string applicationName,
        string commandLine,
        WindowsProcessCreationFlags creationFlags,
        WindowsProcessPipe standardInput,
        WindowsProcessPipe standardOutput,
        WindowsProcessPipe standardError,
        IWindowsStartupAttributeList startupAttributes)
    {
        if (string.IsNullOrWhiteSpace(applicationName))
        {
            throw new ArgumentException("应用程序名不能为空。", nameof(applicationName));
        }

        var nativeStartup = Require<NativeWindowsStartupAttributeList>(startupAttributes);
        var startupInfo = nativeStartup.CreateStartupInfo(
            standardInput.ChildHandle.DangerousGetHandle(),
            standardOutput.ChildHandle.DangerousGetHandle(),
            standardError.ChildHandle.DangerousGetHandle(),
            StartfUseStdHandles);
        var mutableCommandLine = new StringBuilder(commandLine);
        if (!NativeMethods.CreateProcess(
                applicationName,
                mutableCommandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                (uint)creationFlags,
                IntPtr.Zero,
                null,
                ref startupInfo,
                out var processInformation))
        {
            throw LastError(ProcessFailureStage.ProcessCreation);
        }

        return new NativeWindowsProcess(
            new SafeKernelObjectHandle(processInformation.ProcessHandle, ownsHandle: true),
            new SafeKernelObjectHandle(processInformation.ThreadHandle, ownsHandle: true));
    }

    public void AssignProcessToJob(IWindowsJob job, IWindowsProcess process)
    {
        var nativeJob = Require<NativeWindowsJob>(job);
        var nativeProcess = Require<NativeWindowsProcess>(process);
        if (!NativeMethods.AssignProcessToJobObject(nativeJob.Handle, nativeProcess.ProcessHandle))
        {
            throw LastError(ProcessFailureStage.JobAssignment);
        }
    }

    public void ResumePrimaryThread(IWindowsProcess process)
    {
        var nativeProcess = Require<NativeWindowsProcess>(process);
        if (NativeMethods.ResumeThread(nativeProcess.ThreadHandle) == uint.MaxValue)
        {
            throw LastError(ProcessFailureStage.ThreadResume);
        }
    }

    public Task WaitForExitAsync(IWindowsProcess process)
    {
        var nativeProcess = Require<NativeWindowsProcess>(process);
        return Task.Run(() =>
        {
            var waitResult = NativeMethods.WaitForSingleObject(nativeProcess.ProcessHandle, Infinite);
            if (waitResult != 0)
            {
                throw LastError(ProcessFailureStage.ProcessWait);
            }
        });
    }

    public int GetExitCode(IWindowsProcess process)
    {
        var nativeProcess = Require<NativeWindowsProcess>(process);
        if (!NativeMethods.GetExitCodeProcess(nativeProcess.ProcessHandle, out var exitCode))
        {
            throw LastError(ProcessFailureStage.ProcessWait);
        }

        return unchecked((int)exitCode);
    }

    public void TerminateProcess(IWindowsProcess process, uint exitCode)
    {
        var nativeProcess = Require<NativeWindowsProcess>(process);
        if (!NativeMethods.TerminateProcess(nativeProcess.ProcessHandle, exitCode))
        {
            throw LastError(ProcessFailureStage.ProcessTermination);
        }
    }

    public void TerminateJob(IWindowsJob job, uint exitCode)
    {
        var nativeJob = Require<NativeWindowsJob>(job);
        if (!NativeMethods.TerminateJobObject(nativeJob.Handle, exitCode))
        {
            throw LastError(ProcessFailureStage.ProcessTermination);
        }
    }

    private static T Require<T>(object value)
        where T : class
    {
        var typed = value as T;
        if (typed == null)
        {
            throw new ArgumentException("Windows API 接缝对象类型无效。", nameof(value));
        }

        return typed;
    }

    private static WindowsProcessNativeException LastError(ProcessFailureStage stage)
    {
        return new WindowsProcessNativeException(stage, Marshal.GetLastWin32Error());
    }

    private sealed class NativeWindowsProcess : IWindowsProcess
    {
        internal NativeWindowsProcess(
            SafeKernelObjectHandle processHandle,
            SafeKernelObjectHandle threadHandle)
        {
            ProcessHandle = processHandle;
            ThreadHandle = threadHandle;
        }

        internal SafeKernelObjectHandle ProcessHandle { get; }
        internal SafeKernelObjectHandle ThreadHandle { get; }

        public void Dispose()
        {
            ThreadHandle.Dispose();
            ProcessHandle.Dispose();
        }
    }

    private sealed class NativeWindowsJob : IWindowsJob
    {
        internal NativeWindowsJob(SafeKernelObjectHandle handle)
        {
            Handle = handle;
        }

        internal SafeKernelObjectHandle Handle { get; }

        public void Dispose()
        {
            Handle.Dispose();
        }
    }

    private sealed class NativeWindowsStartupAttributeList : IWindowsStartupAttributeList
    {
        private IntPtr attributeList;
        private IntPtr handleList;
        private bool initialized;

        internal NativeWindowsStartupAttributeList(IReadOnlyList<IntPtr> inheritedHandles)
        {
            IntPtr attributeListSize = IntPtr.Zero;
            NativeMethods.InitializeProcThreadAttributeList(
                IntPtr.Zero,
                1,
                0,
                ref attributeListSize);
            attributeList = Marshal.AllocHGlobal(attributeListSize);
            if (!NativeMethods.InitializeProcThreadAttributeList(
                    attributeList,
                    1,
                    0,
                    ref attributeListSize))
            {
                var error = Marshal.GetLastWin32Error();
                Dispose();
                throw new WindowsProcessNativeException(
                    ProcessFailureStage.StartupAttributeConfiguration,
                    error);
            }

            initialized = true;

            handleList = Marshal.AllocHGlobal(IntPtr.Size * inheritedHandles.Count);
            Marshal.Copy(inheritedHandles.ToArray(), 0, handleList, inheritedHandles.Count);
            if (!NativeMethods.UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    ProcThreadAttributeHandleList,
                    handleList,
                    new IntPtr(IntPtr.Size * inheritedHandles.Count),
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();
                Dispose();
                throw new WindowsProcessNativeException(
                    ProcessFailureStage.StartupAttributeConfiguration,
                    error);
            }
        }

        internal StartupInfoEx CreateStartupInfo(
            IntPtr standardInput,
            IntPtr standardOutput,
            IntPtr standardError,
            uint flags)
        {
            return new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Size = Marshal.SizeOf(typeof(StartupInfoEx)),
                    Flags = flags,
                    StandardInput = standardInput,
                    StandardOutput = standardOutput,
                    StandardError = standardError
                },
                AttributeList = attributeList
            };
        }

        public void Dispose()
        {
            if (attributeList != IntPtr.Zero)
            {
                if (initialized)
                {
                    NativeMethods.DeleteProcThreadAttributeList(attributeList);
                    initialized = false;
                }

                Marshal.FreeHGlobal(attributeList);
                attributeList = IntPtr.Zero;
            }

            if (handleList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(handleList);
                handleList = IntPtr.Zero;
            }
        }
    }

    private sealed class SafeKernelObjectHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeKernelObjectHandle()
            : base(ownsHandle: true)
        {
        }

        internal SafeKernelObjectHandle(IntPtr preexistingHandle, bool ownsHandle)
            : base(ownsHandle)
        {
            SetHandle(preexistingHandle);
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        internal bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        internal int Size;
        internal IntPtr Reserved;
        internal IntPtr Desktop;
        internal IntPtr Title;
        internal int X;
        internal int Y;
        internal int XSize;
        internal int YSize;
        internal int XCountChars;
        internal int YCountChars;
        internal int FillAttribute;
        internal uint Flags;
        internal short ShowWindow;
        internal short Reserved2Size;
        internal IntPtr Reserved2;
        internal IntPtr StandardInput;
        internal IntPtr StandardOutput;
        internal IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        internal StartupInfo StartupInfo;
        internal IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal IntPtr ProcessHandle;
        internal IntPtr ThreadHandle;
        internal uint ProcessId;
        internal uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSetSize;
        internal UIntPtr MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        internal JobObjectBasicLimitInformation BasicLimitInformation;
        internal IoCounters IoInfo;
        internal UIntPtr ProcessMemoryLimit;
        internal UIntPtr JobMemoryLimit;
        internal UIntPtr PeakProcessMemoryUsed;
        internal UIntPtr PeakJobMemoryUsed;
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreatePipe(
            out SafeFileHandle readPipe,
            out SafeFileHandle writePipe,
            ref SecurityAttributes pipeAttributes,
            int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetHandleInformation(
            SafeFileHandle handle,
            uint mask,
            uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeKernelObjectHandle CreateJobObject(
            IntPtr jobAttributes,
            string? name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            SafeKernelObjectHandle job,
            int informationClass,
            ref JobObjectExtendedLimitInformation information,
            int informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList,
            int attributeCount,
            int flags,
            ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            IntPtr attribute,
            IntPtr value,
            IntPtr size,
            IntPtr previousValue,
            IntPtr returnSize);

        [DllImport("kernel32.dll")]
        internal static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcess(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string? currentDirectory,
            ref StartupInfoEx startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(
            SafeKernelObjectHandle job,
            SafeKernelObjectHandle process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(SafeKernelObjectHandle thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(
            SafeKernelObjectHandle handle,
            int milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(
            SafeKernelObjectHandle process,
            out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(
            SafeKernelObjectHandle process,
            uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateJobObject(
            SafeKernelObjectHandle job,
            uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }
}
