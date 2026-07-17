using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Sessions;

namespace AssessmentTool.Windows.Processes;

internal interface IProcessRunner
{
    Task<ProcessRunResult> RunAsync(
        ComponentExecutionCandidate executable,
        ProcessRunRequest request,
        CancellationToken cancellationToken);
}

internal abstract class ProcessArgumentPlan
{
    private readonly IReadOnlyList<string> argumentTokens;

    private protected ProcessArgumentPlan(IReadOnlyList<string> argumentTokens)
    {
        if (argumentTokens == null)
        {
            throw new ArgumentNullException(nameof(argumentTokens));
        }

        var tokenSnapshot = argumentTokens.ToArray();
        if (tokenSnapshot.Any(token => token == null))
        {
            throw new ArgumentException("参数 token 不能包含 null。", nameof(argumentTokens));
        }

        this.argumentTokens = new ReadOnlyCollection<string>(tokenSnapshot);
    }

    internal IReadOnlyList<string> ArgumentTokens => argumentTokens;

    internal static ProcessArgumentPlan FromTokens(IReadOnlyList<string> argumentTokens)
    {
        return new GeneralProcessArgumentPlan(argumentTokens);
    }

    private sealed class GeneralProcessArgumentPlan : ProcessArgumentPlan
    {
        internal GeneralProcessArgumentPlan(IReadOnlyList<string> argumentTokens)
            : base(argumentTokens)
        {
        }
    }
}

internal interface IControlledPlinkArgumentPlan
{
}

internal sealed class ProcessRunRequest
{
    private readonly ProcessArgumentPlan argumentPlan;
    private readonly CommandDefinition? command;
    private readonly TimeSpan timeout;
    private readonly bool closeStandardInputWithoutData;
    private readonly Encoding inputEncoding;
    private readonly Encoding outputEncoding;

    internal ProcessRunRequest(
        ProcessArgumentPlan argumentPlan,
        CommandDefinition command,
        Encoding inputEncoding,
        Encoding outputEncoding)
    {
        this.argumentPlan = argumentPlan ?? throw new ArgumentNullException(nameof(argumentPlan));
        this.command = command ?? throw new ArgumentNullException(nameof(command));
        timeout = command.Timeout;
        this.inputEncoding = SnapshotEncoding(
            inputEncoding ?? throw new ArgumentNullException(nameof(inputEncoding)));
        this.outputEncoding = SnapshotEncoding(
            outputEncoding ?? throw new ArgumentNullException(nameof(outputEncoding)));
    }

    internal IReadOnlyList<string> ArgumentTokens => argumentPlan.ArgumentTokens;
    internal CommandDefinition Command => command
        ?? throw new InvalidOperationException("无命令连接检查不包含远程命令。");
    internal Encoding InputEncoding => SnapshotEncoding(inputEncoding);
    internal Encoding OutputEncoding => SnapshotEncoding(outputEncoding);

    internal bool HasControlledPlinkPlan()
    {
        return argumentPlan is IControlledPlinkArgumentPlan;
    }

    internal static ProcessRunRequest CreateWithoutStandardInput(
        ProcessArgumentPlan argumentPlan,
        TimeSpan timeout,
        Encoding outputEncoding)
    {
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        return new ProcessRunRequest(argumentPlan, timeout, outputEncoding);
    }

    internal bool TryGetVerifiedCommand(out CommandDefinition? verifiedCommand)
    {
        verifiedCommand = command;
        return verifiedCommand != null;
    }

    internal TimeSpan GetTimeout()
    {
        return timeout;
    }

    internal byte[] GetStandardInputBytes()
    {
        if (closeStandardInputWithoutData)
        {
            return Array.Empty<byte>();
        }

        return inputEncoding.GetBytes(Command.CommandText.Trim() + "\r\n");
    }

    private ProcessRunRequest(
        ProcessArgumentPlan argumentPlan,
        TimeSpan timeout,
        Encoding outputEncoding)
    {
        this.argumentPlan = argumentPlan ?? throw new ArgumentNullException(nameof(argumentPlan));
        this.timeout = timeout;
        closeStandardInputWithoutData = true;
        inputEncoding = SnapshotEncoding(outputEncoding ?? throw new ArgumentNullException(nameof(outputEncoding)));
        this.outputEncoding = SnapshotEncoding(outputEncoding);
    }

    private static Encoding SnapshotEncoding(Encoding encoding)
    {
        return Encoding.GetEncoding(
            encoding.CodePage,
            encoding.EncoderFallback,
            encoding.DecoderFallback);
    }
}

internal enum ProcessRunOutcome
{
    Succeeded,
    Failed,
    Cancelled,
    TimedOut
}

internal enum ProcessFailureStage
{
    None,
    SafetyValidation,
    PipeCreation,
    JobCreation,
    StartupAttributeConfiguration,
    ProcessCreation,
    JobAssignment,
    ThreadResume,
    StandardInput,
    ProcessWait,
    ProcessTermination
}

internal sealed class ProcessRunResult
{
    private readonly byte[] standardOutput;
    private readonly byte[] standardError;

    private ProcessRunResult(
        ProcessRunOutcome outcome,
        byte[] standardOutput,
        byte[] standardError,
        int? exitCode,
        ProcessFailureStage failureStage,
        string? failureCode,
        int? nativeErrorCode)
    {
        Outcome = outcome;
        this.standardOutput = (standardOutput ?? Array.Empty<byte>()).ToArray();
        this.standardError = (standardError ?? Array.Empty<byte>()).ToArray();
        ExitCode = exitCode;
        FailureStage = failureStage;
        FailureCode = failureCode;
        NativeErrorCode = nativeErrorCode;
    }

    internal ProcessRunOutcome Outcome { get; }
    internal byte[] StandardOutput => standardOutput.ToArray();
    internal byte[] StandardError => standardError.ToArray();
    internal int? ExitCode { get; }
    internal ProcessFailureStage FailureStage { get; }
    internal string? FailureCode { get; }
    internal int? NativeErrorCode { get; }

    internal static ProcessRunResult Completed(byte[] standardOutput, byte[] standardError, int exitCode)
    {
        return new ProcessRunResult(
            exitCode == 0 ? ProcessRunOutcome.Succeeded : ProcessRunOutcome.Failed,
            standardOutput,
            standardError,
            exitCode,
            ProcessFailureStage.None,
            exitCode == 0 ? null : "process-exit-code",
            null);
    }

    internal static ProcessRunResult Rejected(string failureCode)
    {
        return Failed(ProcessFailureStage.SafetyValidation, failureCode, null);
    }

    internal static ProcessRunResult Failed(
        ProcessFailureStage failureStage,
        string failureCode,
        int? nativeErrorCode,
        byte[]? standardOutput = null,
        byte[]? standardError = null)
    {
        return new ProcessRunResult(
            ProcessRunOutcome.Failed,
            standardOutput ?? Array.Empty<byte>(),
            standardError ?? Array.Empty<byte>(),
            null,
            failureStage,
            failureCode,
            nativeErrorCode);
    }

    internal static ProcessRunResult Stopped(
        ProcessRunOutcome outcome,
        byte[] standardOutput,
        byte[] standardError)
    {
        if (outcome != ProcessRunOutcome.Cancelled && outcome != ProcessRunOutcome.TimedOut)
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }

        return new ProcessRunResult(
            outcome,
            standardOutput,
            standardError,
            null,
            ProcessFailureStage.ProcessWait,
            outcome == ProcessRunOutcome.Cancelled ? "cancelled" : "timed-out",
            null);
    }
}
