using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using AssessmentTool.Core.Security;
using Xunit;

namespace AssessmentTool.Core.Tests.Execution;

public sealed class DatabaseDiscoveryRunnerTests
{
    [Fact]
    public async Task Same_outputs_return_only_database_candidates_without_repeating_commands()
    {
        var pack = LoadPack();
        var session = new ScriptedSession(new Dictionary<string, CommandOutput>
        {
            [pack.Commands[0].Id] = Success(pack.Commands[0].Id, "101 postgres-16"),
            [pack.Commands[1].Id] = Success(pack.Commands[1].Id, "postgresql@16-main.service loaded active running PostgreSQL Cluster 16-main"),
            [pack.Commands[2].Id] = Success(pack.Commands[2].Id, ""),
            [pack.Commands[3].Id] = Success(pack.Commands[3].Id, "")
        });

        var result = await CreateRunner(session).RunAsync(pack, new RecordingProgress(), CancellationToken.None);

        Assert.Equal(DatabaseDiscoveryOutcome.Completed, result.Outcome);
        Assert.Equal(pack.Commands.Select(command => command.Id), session.ExecutedIds);
        var candidate = Assert.Single(result.DatabaseCandidates);
        Assert.Equal("PostgreSQL", candidate.Product);
        Assert.Equal("16", candidate.Version);
        Assert.Same(result.DatabaseCandidates, result.Candidates);
        Assert.Empty(result.MiddlewareCandidates);
    }

    [Fact]
    public async Task Same_outputs_return_only_middleware_candidates_without_repeating_commands()
    {
        var pack = LoadPack();
        var session = SessionFor(pack, "101 nginx", "nginx.service loaded active running A high performance web server");

        var result = await CreateRunner(session).RunAsync(pack, new RecordingProgress(), CancellationToken.None);

        Assert.Equal(DatabaseDiscoveryOutcome.Completed, result.Outcome);
        Assert.Equal(pack.Commands.Select(command => command.Id), session.ExecutedIds);
        Assert.Empty(result.DatabaseCandidates);
        var candidate = Assert.Single(result.MiddlewareCandidates);
        Assert.Equal("Nginx", candidate.Product);
    }

    [Fact]
    public async Task Same_outputs_return_database_and_middleware_candidates_without_repeating_commands()
    {
        var pack = LoadPack();
        var session = SessionFor(
            pack,
            "101 postgres-16\n202 nginx",
            "postgresql@16-main.service loaded active running PostgreSQL Cluster 16-main\nnginx.service loaded active running A high performance web server");

        var result = await CreateRunner(session).RunAsync(pack, new RecordingProgress(), CancellationToken.None);

        Assert.Equal(DatabaseDiscoveryOutcome.Completed, result.Outcome);
        Assert.Equal(pack.Commands.Select(command => command.Id), session.ExecutedIds);
        Assert.Equal("PostgreSQL", Assert.Single(result.DatabaseCandidates).Product);
        Assert.Equal("Nginx", Assert.Single(result.MiddlewareCandidates).Product);
    }

    [Fact]
    public async Task Same_outputs_return_no_candidates_without_repeating_commands()
    {
        var pack = LoadPack();
        var session = SessionFor(pack, "101 sshd", "ssh.service loaded active running OpenBSD Secure Shell server");

        var result = await CreateRunner(session).RunAsync(pack, new RecordingProgress(), CancellationToken.None);

        Assert.Equal(DatabaseDiscoveryOutcome.Completed, result.Outcome);
        Assert.Equal(pack.Commands.Select(command => command.Id), session.ExecutedIds);
        Assert.Empty(result.DatabaseCandidates);
        Assert.Empty(result.MiddlewareCandidates);
    }

    [Fact]
    public async Task Missing_optional_container_tools_are_preserved_but_do_not_fail_discovery()
    {
        var pack = LoadPack();
        var session = new ScriptedSession(new Dictionary<string, CommandOutput>
        {
            [pack.Commands[0].Id] = Success(pack.Commands[0].Id, "202 mysqld-8.0"),
            [pack.Commands[1].Id] = Success(pack.Commands[1].Id, "mysql.service loaded active running MySQL 8.0 Community Server"),
            [pack.Commands[2].Id] = MissingOptional(pack.Commands[2].Id),
            [pack.Commands[3].Id] = MissingOptional(pack.Commands[3].Id)
        });

        var result = await CreateRunner(session).RunAsync(pack, new RecordingProgress(), CancellationToken.None);

        Assert.Equal(DatabaseDiscoveryOutcome.Completed, result.Outcome);
        Assert.Equal(4, result.Outputs.Count);
        Assert.Single(result.Candidates);
    }

    [Fact]
    public async Task Required_command_failure_stops_before_later_commands()
    {
        var pack = LoadPack();
        var session = new ScriptedSession(new Dictionary<string, CommandOutput>
        {
            [pack.Commands[0].Id] = Failed(pack.Commands[0].Id)
        });

        var result = await CreateRunner(session).RunAsync(pack, new RecordingProgress(), CancellationToken.None);

        Assert.Equal(DatabaseDiscoveryOutcome.Failed, result.Outcome);
        Assert.Single(result.Outputs);
        Assert.Single(session.ExecutedIds);
        Assert.Empty(result.Candidates);
    }

    [Fact]
    public async Task Optional_container_permission_failure_is_not_silently_treated_as_complete()
    {
        var pack = LoadPack();
        var session = new ScriptedSession(new Dictionary<string, CommandOutput>
        {
            [pack.Commands[0].Id] = Success(pack.Commands[0].Id, "202 mysqld-8.0"),
            [pack.Commands[1].Id] = Success(pack.Commands[1].Id, ""),
            [pack.Commands[2].Id] = Failed(pack.Commands[2].Id),
        });

        var result = await CreateRunner(session).RunAsync(pack, new RecordingProgress(), CancellationToken.None);

        Assert.Equal(DatabaseDiscoveryOutcome.Failed, result.Outcome);
        Assert.Equal(3, result.Outputs.Count);
        Assert.Equal(3, session.ExecutedIds.Count);
    }

    [Fact]
    public async Task Systemd_permission_failure_is_not_silently_treated_as_unavailable()
    {
        var pack = LoadPack();
        var session = new ScriptedSession(new Dictionary<string, CommandOutput>
        {
            [pack.Commands[0].Id] = Success(pack.Commands[0].Id, "202 mysqld-8.0"),
            [pack.Commands[1].Id] = Failed(pack.Commands[1].Id)
        });

        var result = await CreateRunner(session).RunAsync(pack, new RecordingProgress(), CancellationToken.None);

        Assert.Equal(DatabaseDiscoveryOutcome.Failed, result.Outcome);
        Assert.Equal(2, result.Outputs.Count);
        Assert.Equal(2, session.ExecutedIds.Count);
        Assert.Empty(result.Candidates);
    }

    private static DatabaseDiscoveryRunner CreateRunner(IRemoteSession session)
    {
        return new DatabaseDiscoveryRunner(
            session,
            new CommandSafetyPolicy(),
            new HostDatabaseDiscovery(),
            new HostMiddlewareDiscovery());
    }

    private static ScriptedSession SessionFor(CommandPack pack, string processes, string services)
    {
        return new ScriptedSession(new Dictionary<string, CommandOutput>
        {
            [pack.Commands[0].Id] = Success(pack.Commands[0].Id, processes),
            [pack.Commands[1].Id] = Success(pack.Commands[1].Id, services),
            [pack.Commands[2].Id] = Success(pack.Commands[2].Id, ""),
            [pack.Commands[3].Id] = Success(pack.Commands[3].Id, "")
        });
    }

    private static CommandPack LoadPack()
    {
        var json = System.IO.File.ReadAllBytes(System.IO.Path.Combine(
            FindRepositoryRoot(),
            "command-packs",
            "builtin",
            "database-host-discovery-linux.json"));
        using var sha256 = SHA256.Create();
        var hash = string.Concat(sha256.ComputeHash(json).Select(value => value.ToString("x2")));
        return new CommandPackLoader().Load(json, hash);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new System.IO.DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null)
        {
            if (System.IO.File.Exists(System.IO.Path.Combine(directory.FullName, "AssessmentTool.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new System.IO.DirectoryNotFoundException();
    }

    private static CommandOutput Success(string commandId, string output)
    {
        var now = DateTimeOffset.UtcNow;
        return new CommandOutput(commandId, output, "", 0, RemoteExecutionOutcome.Succeeded, null, now, now);
    }

    private static CommandOutput MissingOptional(string commandId)
    {
        var now = DateTimeOffset.UtcNow;
        return new CommandOutput(
            commandId,
            "",
            "command not found",
            127,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.ProcessFailed,
            now,
            now);
    }

    private static CommandOutput Failed(string commandId)
    {
        var now = DateTimeOffset.UtcNow;
        return new CommandOutput(
            commandId,
            "",
            "failed",
            1,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.ProcessFailed,
            now,
            now);
    }

    private sealed class ScriptedSession : IRemoteSession
    {
        private readonly IReadOnlyDictionary<string, CommandOutput> outputs;

        internal ScriptedSession(IReadOnlyDictionary<string, CommandOutput> outputs)
        {
            this.outputs = outputs;
        }

        internal List<string> ExecutedIds { get; } = new List<string>();

        public Task<CommandOutput> ExecuteAsync(CommandDefinition command, CancellationToken cancellationToken)
        {
            ExecutedIds.Add(command.Id);
            return Task.FromResult(outputs[command.Id]);
        }
    }

    private sealed class RecordingProgress : IProgress<CollectionProgress>
    {
        public void Report(CollectionProgress value)
        {
        }
    }
}
