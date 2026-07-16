using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Core.Execution;

public enum CollectionState
{
    Connecting,
    Identifying,
    AwaitingConfirmation,
    PreparingCommands,
    Executing,
    SavingEvidence,
    Completed,
    Failed,
    Stopped
}

public enum CollectionOutcome
{
    Completed,
    NeedsUserConfirmation,
    NoCommandsMatched,
    CommandRejected,
    Failed,
    Stopped
}

public sealed class CollectionProgress
{
    internal CollectionProgress(
        CollectionState state,
        string message,
        string? commandId = null,
        int completedCommands = 0,
        int totalCommands = 0)
    {
        if (!Enum.IsDefined(typeof(CollectionState), state))
        {
            throw new ArgumentOutOfRangeException(nameof(state), state, "采集状态无效。");
        }

        if (string.IsNullOrWhiteSpace(message))
        {
            throw new ArgumentException("采集进度说明不能为空。", nameof(message));
        }

        if (completedCommands < 0 || totalCommands < 0 || completedCommands > totalCommands)
        {
            throw new ArgumentOutOfRangeException(nameof(completedCommands), "采集命令进度无效。");
        }

        State = state;
        Message = message;
        CommandId = commandId;
        CompletedCommands = completedCommands;
        TotalCommands = totalCommands;
    }

    public CollectionState State { get; }
    public string Message { get; }
    public string? CommandId { get; }
    public int CompletedCommands { get; }
    public int TotalCommands { get; }
}

public sealed class CollectionRequest
{
    public CollectionRequest(
        CommandPack commandPack,
        DetectionCandidate? confirmedCandidate = null)
    {
        CommandPack = commandPack ?? throw new ArgumentNullException(nameof(commandPack));

        if (confirmedCandidate != null && confirmedCandidate.Category == TargetCategory.Automatic)
        {
            throw new ArgumentException("人工确认结果必须选择具体对象类别。", nameof(confirmedCandidate));
        }

        ConfirmedCandidate = confirmedCandidate;
    }

    public CommandPack CommandPack { get; }
    public DetectionCandidate? ConfirmedCandidate { get; }
}

public sealed class CollectionResult
{
    internal CollectionResult(
        CollectionOutcome outcome,
        DetectionResult? detection,
        IEnumerable<CommandOutput> identificationOutputs,
        IEnumerable<CommandOutput> commandOutputs,
        string message,
        string? rejectedCommandId = null)
    {
        if (!Enum.IsDefined(typeof(CollectionOutcome), outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "采集结果无效。");
        }

        Outcome = outcome;
        Detection = detection;
        IdentificationOutputs = CopyOutputs(identificationOutputs, nameof(identificationOutputs));
        CommandOutputs = CopyOutputs(commandOutputs, nameof(commandOutputs));
        Message = string.IsNullOrWhiteSpace(message)
            ? throw new ArgumentException("采集结果说明不能为空。", nameof(message))
            : message;
        RejectedCommandId = rejectedCommandId;
    }

    public CollectionOutcome Outcome { get; }
    public DetectionResult? Detection { get; }
    public IReadOnlyList<CommandOutput> IdentificationOutputs { get; }
    public IReadOnlyList<CommandOutput> CommandOutputs { get; }
    public string Message { get; }
    public string? RejectedCommandId { get; }

    private static IReadOnlyList<CommandOutput> CopyOutputs(
        IEnumerable<CommandOutput> outputs,
        string parameterName)
    {
        if (outputs == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        var copied = outputs.ToArray();
        if (copied.Any(output => output == null))
        {
            throw new ArgumentException("执行结果不能包含空项。", parameterName);
        }

        return new ReadOnlyCollection<CommandOutput>(copied);
    }
}
