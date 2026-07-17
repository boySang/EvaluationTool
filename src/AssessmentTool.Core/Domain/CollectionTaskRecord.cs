using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace AssessmentTool.Core.Domain;

public enum CollectionTaskState
{
    Ready = 1,
    Running = 2,
    Stopping = 3,
    Completed = 4,
    Failed = 5,
    Stopped = 6,
    Interrupted = 7
}

public sealed class CollectionTaskCommandSnapshot
{
    public CollectionTaskCommandSnapshot(
        int ordinal,
        string commandPackId,
        string commandPackVersion,
        string commandPackSha256,
        string commandId,
        string commandText,
        string checkItem,
        string resultDescription,
        CommandRiskLevel riskLevel,
        bool isOptional,
        DateTimeOffset safetyValidatedAt)
    {
        if (ordinal < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ordinal), ordinal, "命令顺序不能为负数。");
        }

        if (!Enum.IsDefined(typeof(CommandRiskLevel), riskLevel))
        {
            throw new ArgumentOutOfRangeException(nameof(riskLevel), riskLevel, "命令风险等级无效。");
        }

        if (safetyValidatedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("命令安全校验时间不能为空。", nameof(safetyValidatedAt));
        }

        Ordinal = ordinal;
        CommandPackId = Required(commandPackId, nameof(commandPackId), 200);
        CommandPackVersion = Required(commandPackVersion, nameof(commandPackVersion), 100);
        CommandPackSha256 = Sha256(commandPackSha256, nameof(commandPackSha256));
        CommandId = Required(commandId, nameof(commandId), 200);
        CommandText = Required(commandText, nameof(commandText), 8192);
        CheckItem = Required(checkItem, nameof(checkItem), 200);
        ResultDescription = Required(resultDescription, nameof(resultDescription), 1000);
        RiskLevel = riskLevel;
        IsOptional = isOptional;
        SafetyValidatedAt = safetyValidatedAt.ToUniversalTime();
    }

    public int Ordinal { get; }
    public string CommandPackId { get; }
    public string CommandPackVersion { get; }
    public string CommandPackSha256 { get; }
    public string CommandId { get; }
    public string CommandText { get; }
    public string CheckItem { get; }
    public string ResultDescription { get; }
    public CommandRiskLevel RiskLevel { get; }
    public bool IsOptional { get; }
    public DateTimeOffset SafetyValidatedAt { get; }

    private static string Required(string value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("任务命令快照字段为空、过长或包含控制字符。", parameterName);
        }

        return value;
    }

    private static string Sha256(string value, string parameterName)
    {
        if (value == null || value.Length != 64 || value.Any(character =>
                !((character >= '0' && character <= '9')
                  || (character >= 'a' && character <= 'f')
                  || (character >= 'A' && character <= 'F'))))
        {
            throw new ArgumentException("命令包 SHA-256 无效。", parameterName);
        }

        return value.ToLowerInvariant();
    }
}

public sealed class CollectionTaskRecord
{
    public CollectionTaskRecord(
        CollectionTaskId id,
        ProjectId projectId,
        DeviceId deviceId,
        long identificationRevision,
        ConnectionProtocol connectionProtocol,
        string host,
        int port,
        string userName,
        SshAuthenticationMethod authenticationMethod,
        string hostKeyAlgorithm,
        string hostKeyFingerprint,
        IEnumerable<CollectionTaskCommandSnapshot> commands,
        DateTimeOffset createdAt)
    {
        if (!id.IsValid || !projectId.IsValid || !deviceId.IsValid)
        {
            throw new ArgumentException("任务、项目和设备标识必须初始化。");
        }

        if (identificationRevision < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(identificationRevision));
        }

        if (connectionProtocol != ConnectionProtocol.Ssh)
        {
            throw new ArgumentOutOfRangeException(nameof(connectionProtocol), "当前任务快照仅允许已交付的 SSH 闭环。");
        }

        if (port < 1 || port > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        if (!Enum.IsDefined(typeof(SshAuthenticationMethod), authenticationMethod))
        {
            throw new ArgumentOutOfRangeException(nameof(authenticationMethod));
        }

        if (createdAt == default(DateTimeOffset))
        {
            throw new ArgumentException("任务创建时间不能为空。", nameof(createdAt));
        }

        var copied = (commands ?? throw new ArgumentNullException(nameof(commands))).ToArray();
        if (copied.Length == 0 || copied.Any(command => command == null)
            || !copied.Select(command => command.Ordinal).SequenceEqual(Enumerable.Range(0, copied.Length))
            || copied.Select(command => command.CommandId).Distinct(StringComparer.Ordinal).Count() != copied.Length)
        {
            throw new ArgumentException("任务命令必须非空、顺序连续且标识唯一。", nameof(commands));
        }

        Id = id;
        ProjectId = projectId;
        DeviceId = deviceId;
        IdentificationRevision = identificationRevision;
        ConnectionProtocol = connectionProtocol;
        Host = Required(host, nameof(host), 512);
        Port = port;
        UserName = Required(userName, nameof(userName), 256);
        AuthenticationMethod = authenticationMethod;
        HostKeyAlgorithm = Required(hostKeyAlgorithm, nameof(hostKeyAlgorithm), 100);
        HostKeyFingerprint = Required(hostKeyFingerprint, nameof(hostKeyFingerprint), 1000);
        Commands = new ReadOnlyCollection<CollectionTaskCommandSnapshot>(copied);
        CreatedAt = createdAt.ToUniversalTime();
    }

    public CollectionTaskId Id { get; }
    public ProjectId ProjectId { get; }
    public DeviceId DeviceId { get; }
    public long IdentificationRevision { get; }
    public ConnectionProtocol ConnectionProtocol { get; }
    public string Host { get; }
    public int Port { get; }
    public string UserName { get; }
    public SshAuthenticationMethod AuthenticationMethod { get; }
    public string HostKeyAlgorithm { get; }
    public string HostKeyFingerprint { get; }
    public IReadOnlyList<CollectionTaskCommandSnapshot> Commands { get; }
    public DateTimeOffset CreatedAt { get; }

    private static string Required(string value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("任务连接快照字段为空、过长或包含控制字符。", parameterName);
        }

        return value;
    }
}

public sealed class CollectionTaskEventRecord
{
    public CollectionTaskEventRecord(
        CollectionTaskId taskId,
        long revision,
        CollectionTaskState state,
        int? commandOrdinal,
        string eventCode,
        DateTimeOffset occurredAt)
    {
        if (!taskId.IsValid || revision < 1 || !Enum.IsDefined(typeof(CollectionTaskState), state))
        {
            throw new ArgumentException("任务事件标识、修订或状态无效。");
        }

        if (commandOrdinal < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(commandOrdinal));
        }

        if (string.IsNullOrWhiteSpace(eventCode) || eventCode.Length > 200 || eventCode.Any(char.IsControl))
        {
            throw new ArgumentException("任务事件代码无效。", nameof(eventCode));
        }

        if (occurredAt == default(DateTimeOffset))
        {
            throw new ArgumentException("任务事件时间不能为空。", nameof(occurredAt));
        }

        TaskId = taskId;
        Revision = revision;
        State = state;
        CommandOrdinal = commandOrdinal;
        EventCode = eventCode;
        OccurredAt = occurredAt.ToUniversalTime();
    }

    public CollectionTaskId TaskId { get; }
    public long Revision { get; }
    public CollectionTaskState State { get; }
    public int? CommandOrdinal { get; }
    public string EventCode { get; }
    public DateTimeOffset OccurredAt { get; }
}
