using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Security;

namespace AssessmentTool.Core.Execution;

public enum DatabaseDiscoveryOutcome
{
    Completed,
    Failed,
    Stopped,
    CommandRejected
}

public sealed class DatabaseDiscoveryResult
{
    internal DatabaseDiscoveryResult(
        DatabaseDiscoveryOutcome outcome,
        IEnumerable<CommandOutput> outputs,
        IEnumerable<DatabaseInstanceCandidate> candidates,
        string message)
        : this(
            outcome,
            outputs,
            candidates,
            Array.Empty<MiddlewareInstanceCandidate>(),
            message)
    {
    }

    internal DatabaseDiscoveryResult(
        DatabaseDiscoveryOutcome outcome,
        IEnumerable<CommandOutput> outputs,
        IEnumerable<DatabaseInstanceCandidate> databaseCandidates,
        IEnumerable<MiddlewareInstanceCandidate> middlewareCandidates,
        string message)
    {
        Outcome = outcome;
        Outputs = Copy(outputs, nameof(outputs));
        DatabaseCandidates = Copy(databaseCandidates, nameof(databaseCandidates));
        MiddlewareCandidates = Copy(middlewareCandidates, nameof(middlewareCandidates));
        Message = string.IsNullOrWhiteSpace(message)
            ? throw new ArgumentException("主机软件发现结果说明不能为空。", nameof(message))
            : message;
    }

    public DatabaseDiscoveryOutcome Outcome { get; }
    public IReadOnlyList<CommandOutput> Outputs { get; }
    public IReadOnlyList<DatabaseInstanceCandidate> DatabaseCandidates { get; }
    public IReadOnlyList<DatabaseInstanceCandidate> Candidates => DatabaseCandidates;
    public IReadOnlyList<MiddlewareInstanceCandidate> MiddlewareCandidates { get; }
    public string Message { get; }

    private static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, string parameterName)
        where T : class
    {
        if (source == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        var items = source.ToArray();
        if (items.Any(item => item == null))
        {
            throw new ArgumentException("主机软件发现结果不能包含空项。", parameterName);
        }

        return new ReadOnlyCollection<T>(items);
    }
}

public sealed class DatabaseDiscoveryRunner
{
    private readonly IRemoteSession session;
    private readonly CommandSafetyPolicy safetyPolicy;
    private readonly HostDatabaseDiscovery databaseDiscovery;
    private readonly HostMiddlewareDiscovery middlewareDiscovery;
    private readonly ICollectionExecutionObserver? observer;

    public DatabaseDiscoveryRunner(
        IRemoteSession session,
        CommandSafetyPolicy safetyPolicy,
        HostDatabaseDiscovery discovery,
        ICollectionExecutionObserver? observer = null)
        : this(session, safetyPolicy, discovery, new HostMiddlewareDiscovery(), observer)
    {
    }

    public DatabaseDiscoveryRunner(
        IRemoteSession session,
        CommandSafetyPolicy safetyPolicy,
        HostDatabaseDiscovery databaseDiscovery,
        HostMiddlewareDiscovery middlewareDiscovery,
        ICollectionExecutionObserver? observer = null)
    {
        this.session = session ?? throw new ArgumentNullException(nameof(session));
        this.safetyPolicy = safetyPolicy ?? throw new ArgumentNullException(nameof(safetyPolicy));
        this.databaseDiscovery = databaseDiscovery ?? throw new ArgumentNullException(nameof(databaseDiscovery));
        this.middlewareDiscovery = middlewareDiscovery ?? throw new ArgumentNullException(nameof(middlewareDiscovery));
        this.observer = observer;
    }

    public async Task<DatabaseDiscoveryResult> RunAsync(
        CommandPack commandPack,
        IProgress<CollectionProgress> progress,
        CancellationToken cancellationToken)
    {
        if (commandPack == null)
        {
            throw new ArgumentNullException(nameof(commandPack));
        }

        if (progress == null)
        {
            throw new ArgumentNullException(nameof(progress));
        }

        var outputs = new List<CommandOutput>();
        try
        {
            for (var index = 0; index < commandPack.Commands.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var command = commandPack.Commands[index];
                var safety = safetyPolicy.Validate(command);
                if (!safety.Allowed)
                {
                    progress.Report(new CollectionProgress(
                        CollectionState.Failed,
                        "数据库与中间件发现命令未通过只读安全复核，已阻止执行。",
                        command.Id,
                        index,
                        commandPack.Commands.Count));
                    return Result(DatabaseDiscoveryOutcome.CommandRejected, outputs, safety.Message);
                }

                progress.Report(new CollectionProgress(
                    CollectionState.Executing,
                    "正在读取数据库与中间件进程、服务或容器的最少必要元数据。",
                    command.Id,
                    index,
                    commandPack.Commands.Count));
                var output = await session.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
                if (output == null || !string.Equals(output.CommandId, command.Id, StringComparison.Ordinal))
                {
                    return Result(
                        DatabaseDiscoveryOutcome.Failed,
                        outputs,
                        "会话返回结果与主机软件发现命令不匹配。");
                }

                outputs.Add(output);
                if (observer != null)
                {
                    await observer.OnCommandCompletedAsync(command, output, CancellationToken.None)
                        .ConfigureAwait(false);
                }

                if (output.Outcome == RemoteExecutionOutcome.Succeeded)
                {
                    continue;
                }

                if (command.IsOptional
                    && output.Outcome == RemoteExecutionOutcome.Failed
                    && output.FailureCategory == RemoteFailureCategory.ProcessFailed
                    && output.ExitCode == 127)
                {
                    continue;
                }

                if (output.Outcome == RemoteExecutionOutcome.Stopped)
                {
                    return Result(DatabaseDiscoveryOutcome.Stopped, outputs, output.UserErrorMessage);
                }

                return Result(DatabaseDiscoveryOutcome.Failed, outputs, output.UserErrorMessage);
            }

            progress.Report(new CollectionProgress(
                CollectionState.Completed,
                "数据库与中间件主机只读发现已完成，发现结果需要人工确认。",
                completedCommands: commandPack.Commands.Count,
                totalCommands: commandPack.Commands.Count));
            return new DatabaseDiscoveryResult(
                DatabaseDiscoveryOutcome.Completed,
                outputs,
                databaseDiscovery.Detect(outputs),
                middlewareDiscovery.Detect(outputs),
                "数据库与中间件主机只读发现已完成。");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Result(DatabaseDiscoveryOutcome.Stopped, outputs, "主机软件发现已安全停止。");
        }
        catch (Exception)
        {
            return Result(DatabaseDiscoveryOutcome.Failed, outputs, "主机软件发现发生异常，已停止后续命令。");
        }
    }

    private DatabaseDiscoveryResult Result(
        DatabaseDiscoveryOutcome outcome,
        IEnumerable<CommandOutput> outputs,
        string message)
    {
        return new DatabaseDiscoveryResult(
            outcome,
            outputs,
            Array.Empty<DatabaseInstanceCandidate>(),
            Array.Empty<MiddlewareInstanceCandidate>(),
            message);
    }
}
