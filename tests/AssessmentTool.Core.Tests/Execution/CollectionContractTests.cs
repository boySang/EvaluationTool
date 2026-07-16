using System;
using System.Collections.Generic;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using Xunit;

namespace AssessmentTool.Core.Tests.Execution;

public sealed class CollectionContractTests
{
    [Fact]
    public void Collection_contracts_expose_only_read_only_properties()
    {
        Assert.All(typeof(CollectionProgress).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.All(typeof(CollectionRequest).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.All(typeof(CollectionResult).GetProperties(), property => Assert.False(property.CanWrite));
    }

    [Fact]
    public void Progress_rejects_undefined_state()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CollectionProgress((CollectionState)int.MaxValue, "测试进度"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Progress_rejects_empty_message(string? message)
    {
        Assert.Throws<ArgumentException>(() =>
            new CollectionProgress(CollectionState.Connecting, message!));
    }

    [Theory]
    [InlineData(-1, 0)]
    [InlineData(0, -1)]
    [InlineData(2, 1)]
    public void Progress_rejects_invalid_command_counts(int completedCommands, int totalCommands)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CollectionProgress(
                CollectionState.Executing,
                "测试进度",
                completedCommands: completedCommands,
                totalCommands: totalCommands));
    }

    [Fact]
    public void Progress_accepts_empty_command_scope()
    {
        var progress = new CollectionProgress(CollectionState.Connecting, "正在连接");

        Assert.Null(progress.CommandId);
        Assert.Equal(0, progress.CompletedCommands);
        Assert.Equal(0, progress.TotalCommands);
    }

    [Fact]
    public void Request_rejects_null_command_pack()
    {
        Assert.Throws<ArgumentNullException>(() => new CollectionRequest(null!));
    }

    [Fact]
    public void Request_rejects_automatic_manual_selection()
    {
        var automatic = new DetectionCandidate(
            TargetCategory.Automatic,
            vendor: null,
            productFamily: null,
            model: null,
            version: null,
            evidence: "测试识别依据",
            confidence: 0.50);

        Assert.Throws<ArgumentException>(() => new CollectionRequest(EmptyPack(), automatic));
    }

    [Fact]
    public void Result_copies_output_lists_and_exposes_read_only_snapshots()
    {
        var identificationOutput = Output("identify");
        var commandOutput = Output("collect");
        var identificationOutputs = new List<CommandOutput> { identificationOutput };
        var commandOutputs = new List<CommandOutput> { commandOutput };

        var result = new CollectionResult(
            CollectionOutcome.Completed,
            detection: null,
            identificationOutputs,
            commandOutputs,
            "采集完成");

        identificationOutputs.Clear();
        commandOutputs.Clear();

        Assert.Same(identificationOutput, Assert.Single(result.IdentificationOutputs));
        Assert.Same(commandOutput, Assert.Single(result.CommandOutputs));
        Assert.Throws<NotSupportedException>(() =>
            ((ICollection<CommandOutput>)result.IdentificationOutputs).Add(Output("another-identify")));
        Assert.Throws<NotSupportedException>(() =>
            ((ICollection<CommandOutput>)result.CommandOutputs).Add(Output("another-collect")));
    }

    [Fact]
    public void Result_accepts_empty_output_lists()
    {
        var result = new CollectionResult(
            CollectionOutcome.NoCommandsMatched,
            detection: null,
            Array.Empty<CommandOutput>(),
            Array.Empty<CommandOutput>(),
            "没有匹配命令");

        Assert.Empty(result.IdentificationOutputs);
        Assert.Empty(result.CommandOutputs);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Result_rejects_empty_message(string? message)
    {
        Assert.Throws<ArgumentException>(() =>
            new CollectionResult(
                CollectionOutcome.Completed,
                detection: null,
                Array.Empty<CommandOutput>(),
                Array.Empty<CommandOutput>(),
                message!));
    }

    [Fact]
    public void Result_rejects_undefined_outcome()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CollectionResult(
                (CollectionOutcome)int.MaxValue,
                detection: null,
                Array.Empty<CommandOutput>(),
                Array.Empty<CommandOutput>(),
                "测试结果"));
    }

    [Fact]
    public void Result_rejects_null_output_lists()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new CollectionResult(
                CollectionOutcome.Completed,
                detection: null,
                identificationOutputs: null!,
                Array.Empty<CommandOutput>(),
                "测试结果"));
        Assert.Throws<ArgumentNullException>(() =>
            new CollectionResult(
                CollectionOutcome.Completed,
                detection: null,
                Array.Empty<CommandOutput>(),
                commandOutputs: null!,
                "测试结果"));
    }

    [Fact]
    public void Result_rejects_null_items_in_output_lists()
    {
        Assert.Throws<ArgumentException>(() =>
            new CollectionResult(
                CollectionOutcome.Completed,
                detection: null,
                new CommandOutput[] { null! },
                Array.Empty<CommandOutput>(),
                "测试结果"));
        Assert.Throws<ArgumentException>(() =>
            new CollectionResult(
                CollectionOutcome.Completed,
                detection: null,
                Array.Empty<CommandOutput>(),
                new CommandOutput[] { null! },
                "测试结果"));
    }

    private static CommandPack EmptyPack()
    {
        return new CommandPack(
            "test-pack",
            "Contract test pack",
            "1.0.0",
            "urn:assessment-tool:test-fixture",
            new string('0', 64),
            Array.Empty<CommandDefinition>());
    }

    private static CommandOutput Output(string commandId)
    {
        var timestamp = new DateTimeOffset(2026, 7, 16, 8, 0, 0, TimeSpan.Zero);
        return new CommandOutput(
            commandId,
            "测试输出",
            string.Empty,
            0,
            RemoteExecutionOutcome.Succeeded,
            failureCategory: null,
            timestamp,
            timestamp.AddSeconds(1));
    }
}
