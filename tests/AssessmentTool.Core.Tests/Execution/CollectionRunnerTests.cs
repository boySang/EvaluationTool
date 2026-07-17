using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using AssessmentTool.Core.Security;
using Xunit;

namespace AssessmentTool.Core.Tests.Execution;

public sealed class CollectionRunnerTests
{
    [Fact]
    public async Task Low_confidence_detection_stops_before_collection_commands()
    {
        var session = new FakeSession("VendorA Network OS 7.2 Model X100");

        var result = await Runner(session, confidence: 0.80).RunAsync(
            Request(CollectionCommand("collect-version", "show version")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.NeedsUserConfirmation, result.Outcome);
        Assert.DoesNotContain(session.Commands, command => command.Id.StartsWith("collect-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unsafe_command_is_rejected_before_session_receives_it()
    {
        var session = new FakeSession("VendorA Network OS 7.2 Model X100");
        var unsafeCommand = CollectionCommand("collect-unsafe", "configure terminal");

        var result = await Runner(session).RunAsync(
            Request(unsafeCommand),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.CommandRejected, result.Outcome);
        Assert.DoesNotContain(session.Commands, command => command.Id == unsafeCommand.Id);
        Assert.DoesNotContain("configure terminal", session.CommandTexts);
    }

    [Fact]
    public async Task Cancellation_preserves_outputs_completed_before_the_next_command()
    {
        using var cancellation = new CancellationTokenSource();
        var session = new FakeSession("VendorA Network OS 7.2 Model X100")
        {
            AfterExecute = command =>
            {
                if (command.Id == "collect-first")
                {
                    cancellation.Cancel();
                }
            }
        };

        var result = await Runner(session).RunAsync(
            Request(
                CollectionCommand("collect-first", "show version"),
                CollectionCommand("collect-second", "show clock")),
            new ProgressRecorder(),
            cancellation.Token);

        Assert.Equal(CollectionOutcome.Stopped, result.Outcome);
        Assert.Equal("collect-first", Assert.Single(result.CommandOutputs).CommandId);
        Assert.DoesNotContain(session.Commands, command => command.Id == "collect-second");
    }

    [Fact]
    public async Task Successful_collection_reports_states_in_explicit_order()
    {
        var progress = new ProgressRecorder();

        var result = await Runner(new FakeSession("VendorA Network OS 7.2 Model X100")).RunAsync(
            Request(CollectionCommand("collect-version", "show version")),
            progress,
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.Completed, result.Outcome);
        Assert.Equal(
            new[]
            {
                CollectionState.Connecting,
                CollectionState.Identifying,
                CollectionState.PreparingCommands,
                CollectionState.Executing,
                CollectionState.Completed
            },
            progress.States);
    }

    [Fact]
    public async Task Observer_locks_plan_before_collection_and_receives_each_output_immediately()
    {
        var observer = new RecordingExecutionObserver();
        var session = new FakeSession("VendorA Network OS 7.2 Model X100");
        var runner = new CollectionRunner(
            session,
            new[] { IdentificationCommand() },
            new[] { IdentificationRuleFor(0.95) },
            new DetectionEngine(),
            new CommandMatcher(),
            new CommandSafetyPolicy(),
            observer);

        var result = await runner.RunAsync(
            Request(CollectionCommand("collect-version", "show version")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.Completed, result.Outcome);
        Assert.Equal(
            new[]
            {
                "output:identify-version",
                "plan:collect-version",
                "output:collect-version"
            },
            observer.Events);
    }

    [Fact]
    public async Task Confirmation_candidate_must_match_the_current_detection_result()
    {
        var first = await Runner(
                new FakeSession("VendorA Network OS 7.2 Model X100"),
                confidence: 0.80)
            .RunAsync(
                Request(CollectionCommand("collect-version", "show version")),
                new ProgressRecorder(),
                CancellationToken.None);
        var candidate = Assert.Single(Assert.IsType<DetectionResult>(first.Detection).Candidates);
        var tampered = new DetectionCandidate(
            candidate.Category,
            candidate.Vendor,
            candidate.ProductFamily,
            "X999",
            candidate.Version,
            candidate.Evidence,
            candidate.Confidence);

        var session = new FakeSession("VendorA Network OS 7.2 Model X100");
        var result = await Runner(session, confidence: 0.80).RunAsync(
            RequestWithConfirmation(tampered, CollectionCommand("collect-version", "show version")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.NeedsUserConfirmation, result.Outcome);
        Assert.DoesNotContain(session.Commands, command => command.Id.StartsWith("collect-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Restored_candidate_is_revalidated_even_when_current_detection_is_high_confidence()
    {
        var staleCandidate = new DetectionCandidate(
            TargetCategory.NetworkDevice,
            "VendorA",
            "Network OS",
            "X999",
            "7.2",
            "VendorA Network OS 7.2 Model X999",
            0.95);
        var session = new FakeSession("VendorA Network OS 7.2 Model X100");

        var result = await Runner(session, confidence: 0.95).RunAsync(
            RequestWithConfirmation(staleCandidate, CollectionCommand("collect-version", "show version")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.NeedsUserConfirmation, result.Outcome);
        Assert.DoesNotContain(session.Commands, command => command.Id.StartsWith("collect-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Confirmed_candidate_preserves_original_confidence_and_allows_matching()
    {
        var first = await Runner(
                new FakeSession("VendorA Network OS 7.2 Model X100"),
                confidence: 0.80)
            .RunAsync(
                Request(CollectionCommand("collect-version", "show version")),
                new ProgressRecorder(),
                CancellationToken.None);
        var candidate = Assert.Single(Assert.IsType<DetectionResult>(first.Detection).Candidates);

        var result = await Runner(
                new FakeSession("VendorA Network OS 7.2 Model X100"),
                confidence: 0.80)
            .RunAsync(
                RequestWithConfirmation(candidate, CollectionCommand("collect-version", "show version")),
                new ProgressRecorder(),
                CancellationToken.None);

        Assert.Equal(CollectionOutcome.Completed, result.Outcome);
        var confirmed = Assert.IsType<DetectionResult>(result.Detection);
        Assert.True(confirmed.WasUserConfirmed);
        Assert.Equal(0.80, Assert.Single(confirmed.Candidates).Confidence);
    }

    [Fact]
    public async Task Session_output_must_match_the_command_that_was_sent()
    {
        var session = new FakeSession("VendorA Network OS 7.2 Model X100")
        {
            ReturnedCommandId = command => command.Id == "collect-version" ? "another-command" : command.Id
        };

        var result = await Runner(session).RunAsync(
            Request(CollectionCommand("collect-version", "show version")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.Failed, result.Outcome);
        Assert.Empty(result.CommandOutputs);
    }

    [Fact]
    public async Task Timed_out_partial_output_is_preserved_but_not_reported_as_completed()
    {
        var session = new FakeSession("VendorA Network OS 7.2 Model X100")
        {
            TimedOutCommandId = "collect-version"
        };

        var result = await Runner(session).RunAsync(
            Request(CollectionCommand("collect-version", "show version")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.Stopped, result.Outcome);
        var output = Assert.Single(result.CommandOutputs);
        Assert.Equal(RemoteExecutionOutcome.Stopped, output.Outcome);
        Assert.Contains("partial", output.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Empty_successful_output_is_not_reported_as_completed()
    {
        var session = new FakeSession("VendorA Network OS 7.2 Model X100")
        {
            EmptyOutputCommandId = "collect-version"
        };

        var result = await Runner(session).RunAsync(
            Request(CollectionCommand("collect-version", "show version")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.Failed, result.Outcome);
        Assert.Empty(Assert.Single(result.CommandOutputs).StandardOutput);
    }

    [Fact]
    public async Task Optional_command_not_found_is_preserved_and_does_not_stop_later_commands()
    {
        var session = new FakeSession("VendorA Network OS 7.2 Model X100")
        {
            FailedCommandId = "collect-optional",
            FailedExitCode = 127
        };

        var result = await Runner(session).RunAsync(
            Request(
                CollectionCommand("collect-optional", "show version", isOptional: true),
                CollectionCommand("collect-required", "show clock")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.Completed, result.Outcome);
        Assert.Equal(2, result.CommandOutputs.Count);
        Assert.Equal(RemoteExecutionOutcome.Failed, result.CommandOutputs[0].Outcome);
        Assert.Contains(session.Commands, command => command.Id == "collect-required");
    }

    [Fact]
    public async Task Optional_command_failure_other_than_not_found_still_stops_collection()
    {
        var session = new FakeSession("VendorA Network OS 7.2 Model X100")
        {
            FailedCommandId = "collect-optional",
            FailedExitCode = 1
        };

        var result = await Runner(session).RunAsync(
            Request(
                CollectionCommand("collect-optional", "show version", isOptional: true),
                CollectionCommand("collect-required", "show clock")),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.Failed, result.Outcome);
        Assert.DoesNotContain(session.Commands, command => command.Id == "collect-required");
    }

    [Fact]
    public async Task No_matching_commands_is_not_reported_as_completed()
    {
        var result = await Runner(new FakeSession("VendorA Network OS 7.2 Model X100")).RunAsync(
            Request(ServerCommand()),
            new ProgressRecorder(),
            CancellationToken.None);

        Assert.Equal(CollectionOutcome.NoCommandsMatched, result.Outcome);
        Assert.Empty(result.CommandOutputs);
    }

    [Fact]
    public void Identification_commands_require_unique_ids_and_identify_purpose()
    {
        var session = new FakeSession("VendorA Network OS 7.2 Model X100");
        var identify = IdentificationCommand();

        Assert.Throws<ArgumentException>(() => new CollectionRunner(
            session,
            new[] { identify, identify },
            new[] { IdentificationRuleFor(0.95) },
            new DetectionEngine(),
            new CommandMatcher(),
            new CommandSafetyPolicy()));
        Assert.Throws<ArgumentException>(() => new CollectionRunner(
            session,
            new[] { CollectionCommand("collect-version", "show version") },
            new[] { IdentificationRuleFor(0.95) },
            new DetectionEngine(),
            new CommandMatcher(),
            new CommandSafetyPolicy()));
    }

    private static CollectionRunner Runner(FakeSession session, double confidence = 0.95)
    {
        return new CollectionRunner(
            session,
            new[] { IdentificationCommand() },
            new[] { IdentificationRuleFor(confidence) },
            new DetectionEngine(),
            new CommandMatcher(),
            new CommandSafetyPolicy());
    }

    private static CollectionRequest Request(params CommandDefinition[] commands)
    {
        return new CollectionRequest(Pack(commands));
    }

    private static CollectionRequest RequestWithConfirmation(
        DetectionCandidate confirmedCandidate,
        params CommandDefinition[] commands)
    {
        return new CollectionRequest(Pack(commands), confirmedCandidate);
    }

    private static CommandPack Pack(params CommandDefinition[] commands)
    {
        return new CommandPack(
            "test-pack",
            "Task 8 test pack",
            "1.0.0",
            "urn:assessment-tool:test-fixture",
            new string('0', 64),
            commands);
    }

    private static IdentificationRule IdentificationRuleFor(double confidence)
    {
        return IdentificationRule.CreateVerified(
            TargetCategory.NetworkDevice,
            @"^(?<vendor>VendorA) (?<productFamily>Network OS) (?<version>7\.2) Model (?<model>X100)$",
            confidence,
            "urn:assessment-tool:test-fixture");
    }

    private static CommandDefinition IdentificationCommand()
    {
        return Command(
            "identify-version",
            "show version",
            TargetCategory.NetworkDevice,
            vendor: null,
            productFamily: null,
            checkItem: "IDENTIFY");
    }

    private static CommandDefinition CollectionCommand(
        string id,
        string commandText,
        bool isOptional = false)
    {
        return Command(
            id,
            commandText,
            TargetCategory.NetworkDevice,
            "VendorA",
            "Network OS",
            "AC-1",
            isOptional);
    }

    private static CommandDefinition ServerCommand()
    {
        return Command("collect-server", "uname -a", TargetCategory.Server, null, null, "AC-1");
    }

    private static CommandDefinition Command(
        string id,
        string commandText,
        TargetCategory category,
        string? vendor,
        string? productFamily,
        string checkItem,
        bool isOptional = false)
    {
        return new CommandDefinition(
            id,
            id,
            category,
            commandText,
            VerificationStatus.Verified,
            isReadOnly: true,
            vendor,
            productFamily,
            minimumVersion: null,
            maximumVersion: null,
            checkItem,
            modelRange: "*",
            accountRequirement: "只读审计账户",
            CommandRiskLevel.Low,
            TimeSpan.FromSeconds(30),
            PagingBehavior.DisablePaging,
            resultDescription: "测试输出",
            new DateTime(2025, 2, 3),
            officialSource: "urn:assessment-tool:test-fixture",
            isOptional);
    }

    private sealed class ProgressRecorder : IProgress<CollectionProgress>
    {
        private readonly List<CollectionState> states = new List<CollectionState>();

        public IReadOnlyList<CollectionState> States => states;

        public void Report(CollectionProgress value)
        {
            states.Add(value.State);
        }
    }

    private sealed class RecordingExecutionObserver : ICollectionExecutionObserver
    {
        private readonly List<string> events = new List<string>();

        public IReadOnlyList<string> Events => events;

        public Task OnPlanReadyAsync(
            DetectionResult detection,
            IReadOnlyList<CommandDefinition> commands,
            CancellationToken cancellationToken)
        {
            events.Add("plan:" + string.Join(",", commands.Select(command => command.Id)));
            return Task.CompletedTask;
        }

        public Task OnCommandCompletedAsync(
            CommandDefinition command,
            CommandOutput output,
            CancellationToken cancellationToken)
        {
            events.Add("output:" + command.Id);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeSession : IRemoteSession
    {
        private readonly string identificationTranscript;
        private readonly List<CommandDefinition> commands = new List<CommandDefinition>();

        public FakeSession(string identificationTranscript)
        {
            this.identificationTranscript = identificationTranscript;
        }

        public Action<CommandDefinition>? AfterExecute { get; set; }
        public Func<CommandDefinition, string>? ReturnedCommandId { get; set; }
        public string? TimedOutCommandId { get; set; }
        public string? EmptyOutputCommandId { get; set; }
        public string? FailedCommandId { get; set; }
        public int FailedExitCode { get; set; } = 1;
        public IReadOnlyList<CommandDefinition> Commands => commands;
        public IReadOnlyList<string> CommandTexts => commands.Select(command => command.CommandText).ToArray();

        public Task<CommandOutput> ExecuteAsync(
            CommandDefinition command,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            commands.Add(command);

            var output = command.Id == "identify-version"
                ? identificationTranscript
                : "completed:" + command.Id;
            if (string.Equals(command.Id, EmptyOutputCommandId, StringComparison.Ordinal))
            {
                output = string.Empty;
            }
            var timestamp = new DateTimeOffset(2026, 7, 16, 8, 0, 0, TimeSpan.Zero);
            var timedOut = string.Equals(command.Id, TimedOutCommandId, StringComparison.Ordinal);
            var failed = string.Equals(command.Id, FailedCommandId, StringComparison.Ordinal);
            var result = new CommandOutput(
                ReturnedCommandId?.Invoke(command) ?? command.Id,
                timedOut ? "partial:" + command.Id : output,
                failed ? "command not found" : string.Empty,
                timedOut ? null : failed ? FailedExitCode : 0,
                timedOut
                    ? RemoteExecutionOutcome.Stopped
                    : failed ? RemoteExecutionOutcome.Failed : RemoteExecutionOutcome.Succeeded,
                timedOut
                    ? RemoteFailureCategory.TimedOut
                    : failed ? RemoteFailureCategory.ProcessFailed : null,
                timestamp,
                timestamp.AddSeconds(1));

            AfterExecute?.Invoke(command);
            return Task.FromResult(result);
        }
    }
}
