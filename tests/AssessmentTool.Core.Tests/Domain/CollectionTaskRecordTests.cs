using System;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Domain;

public sealed class CollectionTaskRecordTests
{
    [Fact]
    public void Task_snapshot_requires_contiguous_unique_read_only_plan_metadata()
    {
        var command = CreateCommand(0, "command-1");
        var task = CreateTask(command);

        Assert.Equal(CollectionTaskId.Parse(task.Id.ToString()), task.Id);
        Assert.Same(command, Assert.Single(task.Commands));
        Assert.Equal(TimeSpan.Zero, task.CreatedAt.Offset);
        Assert.Throws<ArgumentException>(() => CreateTask(CreateCommand(1, "command-1")));
        Assert.Throws<ArgumentException>(() => CreateTask(
            CreateCommand(0, "duplicate"),
            CreateCommand(1, "duplicate")));
    }

    [Fact]
    public void Task_command_rejects_invalid_pack_hash()
    {
        Assert.Throws<ArgumentException>(() => new CollectionTaskCommandSnapshot(
            0,
            "pack",
            "1.0.0",
            "not-a-hash",
            "command-1",
            "uname -a",
            "IDENTIFY",
            "读取系统信息",
            CommandRiskLevel.Low,
            false,
            DateTimeOffset.UtcNow));
    }

    private static CollectionTaskRecord CreateTask(params CollectionTaskCommandSnapshot[] commands)
    {
        return new CollectionTaskRecord(
            CollectionTaskId.New(),
            ProjectId.New(),
            DeviceId.New(),
            1,
            ConnectionProtocol.Ssh,
            "192.0.2.10",
            22,
            "audit-user",
            SshAuthenticationMethod.Password,
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:fixture",
            commands,
            new DateTimeOffset(2026, 7, 18, 8, 0, 0, TimeSpan.FromHours(8)));
    }

    private static CollectionTaskCommandSnapshot CreateCommand(int ordinal, string commandId)
    {
        return new CollectionTaskCommandSnapshot(
            ordinal,
            "generic-linux",
            "1.0.0",
            new string('a', 64),
            commandId,
            "uname -a",
            "IDENTIFY",
            "读取系统信息",
            CommandRiskLevel.Low,
            false,
            DateTimeOffset.UtcNow);
    }
}
