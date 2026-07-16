using System;
using System.Threading;
using System.Threading.Tasks;

namespace AssessmentTool.Core.Domain;

public interface IRemoteSession
{
    Task<CommandOutput> ExecuteAsync(
        CommandDefinition command,
        CancellationToken cancellationToken);
}

public enum RemoteExecutionOutcome
{
    Succeeded,
    Failed,
    Stopped
}

public enum RemoteFailureCategory
{
    AuthenticationFailed,
    HostKeyRejected,
    NetworkFailed,
    TimedOut,
    Cancelled,
    ProcessFailed,
    UnsafeCommand
}

public sealed class CommandOutput
{
    public CommandOutput(
        string commandId,
        string standardOutput,
        string standardError,
        int? exitCode,
        RemoteExecutionOutcome outcome,
        RemoteFailureCategory? failureCategory,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt)
    {
        CommandId = ValidateRequiredText(commandId, nameof(commandId), "命令 ID 不能为空。");
        StandardOutput = standardOutput ?? throw new ArgumentNullException(
            nameof(standardOutput),
            "标准输出不能为空；没有输出时请使用空字符串。");
        StandardError = standardError ?? throw new ArgumentNullException(
            nameof(standardError),
            "标准错误不能为空；没有错误输出时请使用空字符串。");

        if (!Enum.IsDefined(typeof(RemoteExecutionOutcome), outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "远程执行结果无效。");
        }

        if (failureCategory.HasValue &&
            !Enum.IsDefined(typeof(RemoteFailureCategory), failureCategory.Value))
        {
            throw new ArgumentOutOfRangeException(
                nameof(failureCategory),
                failureCategory,
                "远程执行错误分类无效。");
        }

        ValidateTerminalCombination(outcome, exitCode, failureCategory);

        if (completedAt < startedAt)
        {
            throw new ArgumentOutOfRangeException(nameof(completedAt), completedAt, "结束时间不能早于开始时间。");
        }

        ExitCode = exitCode;
        Outcome = outcome;
        FailureCategory = failureCategory;
        StartedAt = startedAt.ToUniversalTime();
        CompletedAt = completedAt.ToUniversalTime();
    }

    public string CommandId { get; }
    public string StandardOutput { get; }
    public string StandardError { get; }
    public int? ExitCode { get; }
    public RemoteExecutionOutcome Outcome { get; }
    public RemoteFailureCategory? FailureCategory { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset CompletedAt { get; }
    public string UserErrorMessage => FailureCategory.HasValue
        ? ToUserErrorMessage(FailureCategory.Value)
        : "命令执行成功。";

    private static string ValidateRequiredText(string value, string parameterName, string errorMessage)
    {
        if (value == null)
        {
            throw new ArgumentNullException(parameterName, errorMessage);
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(errorMessage, parameterName);
        }

        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("命令 ID 不能包含控制字符。", parameterName);
            }
        }

        return value;
    }

    private static void ValidateTerminalCombination(
        RemoteExecutionOutcome outcome,
        int? exitCode,
        RemoteFailureCategory? failureCategory)
    {
        if (outcome == RemoteExecutionOutcome.Succeeded)
        {
            if (!exitCode.HasValue || exitCode.Value != 0)
            {
                throw new ArgumentException("成功结果的退出码必须为 0。", nameof(exitCode));
            }

            if (failureCategory.HasValue)
            {
                throw new ArgumentException("成功结果不能包含错误分类。", nameof(failureCategory));
            }

            return;
        }

        if (!failureCategory.HasValue)
        {
            throw new ArgumentException("失败或停止结果必须包含安全错误分类。", nameof(failureCategory));
        }

        if (exitCode.HasValue && exitCode.Value == 0)
        {
            throw new ArgumentException("失败或停止结果不能使用成功退出码 0。", nameof(exitCode));
        }

        var isStoppedCategory =
            failureCategory.Value == RemoteFailureCategory.Cancelled ||
            failureCategory.Value == RemoteFailureCategory.TimedOut;
        if (outcome == RemoteExecutionOutcome.Stopped && !isStoppedCategory)
        {
            throw new ArgumentException("停止结果只允许使用“已取消”或“已超时”错误分类。", nameof(failureCategory));
        }

        if (outcome == RemoteExecutionOutcome.Failed && isStoppedCategory)
        {
            throw new ArgumentException("失败结果不能使用“已取消”或“已超时”错误分类。", nameof(failureCategory));
        }
    }

    private static string ToUserErrorMessage(RemoteFailureCategory category)
    {
        switch (category)
        {
            case RemoteFailureCategory.AuthenticationFailed:
                return "SSH 身份认证失败，请检查测评账户和凭据。";
            case RemoteFailureCategory.HostKeyRejected:
                return "SSH 主机指纹校验失败，已阻止自动连接，请重新核对设备指纹。";
            case RemoteFailureCategory.NetworkFailed:
                return "网络连接失败，请检查目标地址、端口和网络状态。";
            case RemoteFailureCategory.TimedOut:
                return "远程命令执行超时，任务已安全停止。";
            case RemoteFailureCategory.Cancelled:
                return "远程命令已由用户安全停止。";
            case RemoteFailureCategory.ProcessFailed:
                return "远程执行组件运行失败，请查看已脱敏的诊断信息。";
            case RemoteFailureCategory.UnsafeCommand:
                return "命令未通过只读安全校验，已阻止执行。";
            default:
                throw new ArgumentOutOfRangeException(nameof(category), category, "远程执行错误分类无效。");
        }
    }
}
