using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Security;

namespace AssessmentTool.Core.Execution;

public sealed class CollectionRunner
{
    private readonly IRemoteSession session;
    private readonly IReadOnlyList<CommandDefinition> identificationCommands;
    private readonly IReadOnlyList<IdentificationRule> identificationRules;
    private readonly DetectionEngine detectionEngine;
    private readonly CommandMatcher commandMatcher;
    private readonly CommandSafetyPolicy safetyPolicy;

    public CollectionRunner(
        IRemoteSession session,
        IEnumerable<CommandDefinition> identificationCommands,
        IEnumerable<IdentificationRule> identificationRules,
        DetectionEngine detectionEngine,
        CommandMatcher commandMatcher,
        CommandSafetyPolicy safetyPolicy)
    {
        this.session = session ?? throw new ArgumentNullException(nameof(session));
        this.identificationCommands = CopyIdentificationCommands(
            identificationCommands,
            nameof(identificationCommands));
        this.identificationRules = CopyRequired(
            identificationRules,
            nameof(identificationRules),
            "至少需要一条已验证识别规则。");
        this.detectionEngine = detectionEngine ?? throw new ArgumentNullException(nameof(detectionEngine));
        this.commandMatcher = commandMatcher ?? throw new ArgumentNullException(nameof(commandMatcher));
        this.safetyPolicy = safetyPolicy ?? throw new ArgumentNullException(nameof(safetyPolicy));
    }

    public async Task<CollectionResult> RunAsync(
        CollectionRequest request,
        IProgress<CollectionProgress> progress,
        CancellationToken cancellationToken)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (progress == null)
        {
            throw new ArgumentNullException(nameof(progress));
        }

        var identificationOutputs = new List<CommandOutput>();
        var commandOutputs = new List<CommandOutput>();
        DetectionResult? detection = null;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            Report(progress, CollectionState.Connecting, "正在建立受控只读会话。");
            Report(progress, CollectionState.Identifying, "正在执行固定的低风险识别命令。");

            foreach (var command in identificationCommands)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var rejected = RejectUnsafe(
                    command,
                    detection,
                    identificationOutputs,
                    commandOutputs,
                    progress);
                if (rejected != null)
                {
                    return rejected;
                }

                var output = await session.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
                if (!IsOutputFor(command, output))
                {
                    return MismatchedOutput(
                        command.Id,
                        detection,
                        identificationOutputs,
                        commandOutputs,
                        progress);
                }

                identificationOutputs.Add(output);
                var terminal = FinishAfterNonSuccess(
                    command,
                    output,
                    detection,
                    identificationOutputs,
                    commandOutputs,
                    progress);
                if (terminal != null)
                {
                    return terminal;
                }
            }

            var transcript = BuildIdentificationTranscript(identificationOutputs);
            detection = string.IsNullOrWhiteSpace(transcript)
                ? new DetectionResult(Array.Empty<DetectionCandidate>())
                : detectionEngine.Detect(transcript, identificationRules);

            if (detection.RequiresUserConfirmation)
            {
                if (request.ConfirmedCandidate == null)
                {
                    Report(progress, CollectionState.AwaitingConfirmation, "识别结果不确定，需要人工选择后才能执行采集命令。");
                    return new CollectionResult(
                        CollectionOutcome.NeedsUserConfirmation,
                        detection,
                        identificationOutputs,
                        commandOutputs,
                        "识别结果不确定，未执行任何采集命令。");
                }

                try
                {
                    detection = detection.Confirm(request.ConfirmedCandidate);
                }
                catch (ArgumentException)
                {
                    Report(progress, CollectionState.AwaitingConfirmation, "人工确认结果已失效或不属于本次识别，请重新选择。");
                    return new CollectionResult(
                        CollectionOutcome.NeedsUserConfirmation,
                        detection,
                        identificationOutputs,
                        commandOutputs,
                        "人工确认结果无效，未执行任何采集命令，请重新选择当前候选项。");
                }
            }

            Report(progress, CollectionState.PreparingCommands, "正在匹配已验证的只读命令包。");
            var commands = commandMatcher.Match(request.CommandPack, detection);
            if (commands.Count == 0)
            {
                Report(progress, CollectionState.Failed, "当前识别结果没有匹配到已验证的只读命令。");
                return new CollectionResult(
                    CollectionOutcome.NoCommandsMatched,
                    detection,
                    identificationOutputs,
                    commandOutputs,
                    "没有匹配到可自动执行的已验证只读命令。");
            }

            for (var index = 0; index < commands.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var command = commands[index];
                var rejected = RejectUnsafe(
                    command,
                    detection,
                    identificationOutputs,
                    commandOutputs,
                    progress);
                if (rejected != null)
                {
                    return rejected;
                }

                progress.Report(new CollectionProgress(
                    CollectionState.Executing,
                    "正在执行已验证的只读采集命令。",
                    command.Id,
                    index,
                    commands.Count));

                var output = await session.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
                if (!IsOutputFor(command, output))
                {
                    return MismatchedOutput(
                        command.Id,
                        detection,
                        identificationOutputs,
                        commandOutputs,
                        progress);
                }

                commandOutputs.Add(output);
                var terminal = FinishAfterNonSuccess(
                    command,
                    output,
                    detection,
                    identificationOutputs,
                    commandOutputs,
                    progress);
                if (terminal != null)
                {
                    return terminal;
                }

                if (string.IsNullOrWhiteSpace(output.StandardOutput)
                    && string.IsNullOrWhiteSpace(output.StandardError))
                {
                    Report(progress, CollectionState.Failed, "命令执行成功但没有返回可保存的输出，已停止后续采集。", command.Id);
                    return new CollectionResult(
                        CollectionOutcome.Failed,
                        detection,
                        identificationOutputs,
                        commandOutputs,
                        "命令没有返回可用输出，请检查命令兼容性、权限或连接组件。");
                }
            }

            Report(progress, CollectionState.Completed, "只读采集任务已完成。");
            return new CollectionResult(
                CollectionOutcome.Completed,
                detection,
                identificationOutputs,
                commandOutputs,
                "只读采集任务已完成。");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Report(progress, CollectionState.Stopped, "采集任务已由用户安全停止，已完成输出予以保留。");
            return new CollectionResult(
                CollectionOutcome.Stopped,
                detection,
                identificationOutputs,
                commandOutputs,
                "采集任务已安全停止，未继续执行后续命令。");
        }
        catch (Exception)
        {
            Report(progress, CollectionState.Failed, "采集过程发生异常，已停止后续命令并保留已完成输出。");
            return new CollectionResult(
                CollectionOutcome.Failed,
                detection,
                identificationOutputs,
                commandOutputs,
                "采集过程发生异常，请查看已脱敏的诊断日志。");
        }
    }

    private CollectionResult? RejectUnsafe(
        CommandDefinition command,
        DetectionResult? detection,
        IReadOnlyList<CommandOutput> identificationOutputs,
        IReadOnlyList<CommandOutput> commandOutputs,
        IProgress<CollectionProgress> progress)
    {
        var decision = safetyPolicy.Validate(command);
        if (decision.Allowed)
        {
            return null;
        }

        Report(progress, CollectionState.Failed, "命令未通过只读安全复核，已阻止执行。", command.Id);
        return new CollectionResult(
            CollectionOutcome.CommandRejected,
            detection,
            identificationOutputs,
            commandOutputs,
            decision.Message,
            command.Id);
    }

    private static CollectionResult? FinishAfterNonSuccess(
        CommandDefinition command,
        CommandOutput output,
        DetectionResult? detection,
        IReadOnlyList<CommandOutput> identificationOutputs,
        IReadOnlyList<CommandOutput> commandOutputs,
        IProgress<CollectionProgress> progress)
    {
        if (output.Outcome == RemoteExecutionOutcome.Succeeded)
        {
            return null;
        }

        if (command.IsOptional
            && output.Outcome == RemoteExecutionOutcome.Failed
            && output.FailureCategory == RemoteFailureCategory.ProcessFailed
            && output.ExitCode == 127)
        {
            return null;
        }

        if (output.Outcome == RemoteExecutionOutcome.Stopped)
        {
            Report(progress, CollectionState.Stopped, output.UserErrorMessage, output.CommandId);
            return new CollectionResult(
                CollectionOutcome.Stopped,
                detection,
                identificationOutputs,
                commandOutputs,
                output.UserErrorMessage);
        }

        Report(progress, CollectionState.Failed, output.UserErrorMessage, output.CommandId);
        return new CollectionResult(
            CollectionOutcome.Failed,
            detection,
            identificationOutputs,
            commandOutputs,
            output.UserErrorMessage);
    }

    private static string BuildIdentificationTranscript(IEnumerable<CommandOutput> outputs)
    {
        var transcript = new StringBuilder();
        foreach (var output in outputs)
        {
            if (output.Outcome != RemoteExecutionOutcome.Succeeded)
            {
                continue;
            }

            if (transcript.Length > 0)
            {
                transcript.AppendLine();
            }

            transcript.Append(output.StandardOutput);
        }

        return transcript.ToString();
    }

    private static bool IsOutputFor(CommandDefinition command, CommandOutput output)
    {
        return output != null && string.Equals(command.Id, output.CommandId, StringComparison.Ordinal);
    }

    private static CollectionResult MismatchedOutput(
        string commandId,
        DetectionResult? detection,
        IReadOnlyList<CommandOutput> identificationOutputs,
        IReadOnlyList<CommandOutput> commandOutputs,
        IProgress<CollectionProgress> progress)
    {
        Report(progress, CollectionState.Failed, "会话返回结果与当前命令不匹配，已阻止继续执行。", commandId);
        return new CollectionResult(
            CollectionOutcome.Failed,
            detection,
            identificationOutputs,
            commandOutputs,
            "会话返回结果与当前命令不匹配，请检查连接组件。");
    }

    private static IReadOnlyList<T> CopyRequired<T>(
        IEnumerable<T> source,
        string parameterName,
        string emptyMessage)
        where T : class
    {
        if (source == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        var items = source.ToArray();
        if (items.Length == 0)
        {
            throw new ArgumentException(emptyMessage, parameterName);
        }

        if (items.Any(item => item == null))
        {
            throw new ArgumentException("固定识别列表不能包含空项。", parameterName);
        }

        return new ReadOnlyCollection<T>(items);
    }

    private static IReadOnlyList<CommandDefinition> CopyIdentificationCommands(
        IEnumerable<CommandDefinition> source,
        string parameterName)
    {
        var commands = CopyRequired(source, parameterName, "至少需要一条固定识别命令。");
        if (commands.Count > 8)
        {
            throw new ArgumentException("固定识别命令最多允许 8 条。", parameterName);
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var command in commands)
        {
            if (!string.Equals(command.CheckItem, "IDENTIFY", StringComparison.Ordinal)
                || command.RiskLevel != CommandRiskLevel.Low)
            {
                throw new ArgumentException("固定识别命令必须标记为 IDENTIFY 且风险等级为 Low。", parameterName);
            }

            if (!ids.Add(command.Id))
            {
                throw new ArgumentException("固定识别命令 ID 不能重复。", parameterName);
            }
        }

        return commands;
    }

    private static void Report(
        IProgress<CollectionProgress> progress,
        CollectionState state,
        string message,
        string? commandId = null)
    {
        progress.Report(new CollectionProgress(state, message, commandId));
    }
}
