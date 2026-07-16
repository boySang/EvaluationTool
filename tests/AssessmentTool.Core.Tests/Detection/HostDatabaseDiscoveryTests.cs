using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Detection;

public sealed class HostDatabaseDiscoveryTests
{
    private const string ProcessCommandId = "database-host-discovery-linux-processes";
    private const string ServiceCommandId = "database-host-discovery-linux-services";
    private const string DockerCommandId = "database-host-discovery-linux-docker-containers";
    private const string PodmanCommandId = "database-host-discovery-linux-podman-containers";

    [Theory]
    [InlineData(
        "PostgreSQL",
        "15",
        "postgresql@15-main.service",
        " 1042 postgres-15     /usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main")]
    [InlineData(
        "MySQL",
        "8.0",
        "mysql.service",
        " 2051 mysqld-8.0      /usr/sbin/mysqld-8.0 --defaults-file=/etc/mysql/my.cnf")]
    [InlineData(
        "MariaDB",
        "10.11",
        "mariadb.service",
        " 3099 mariadbd-10.11  /usr/sbin/mariadbd-10.11 --defaults-file=/etc/mysql/mariadb.cnf")]
    public void Detects_supported_native_database_services(
        string product,
        string version,
        string serviceName,
        string evidence)
    {
        var candidates = new HostDatabaseDiscovery().Detect(LoadFixture("linux-native-databases.txt"));

        var candidate = Assert.Single(candidates, item => item.Product == product);

        Assert.Equal(version, candidate.Version);
        Assert.Equal(DatabaseInstallationType.LocalService, candidate.InstallationType);
        Assert.Equal(serviceName, candidate.InstanceName);
        Assert.Null(candidate.PortEvidence);
        Assert.Equal(evidence, candidate.Evidence);
        Assert.False(candidate.RequiresUserConfirmation);
        Assert.InRange(candidate.Confidence, 0.0, 1.0);
    }

    [Theory]
    [InlineData(
        "PostgreSQL",
        "16.3",
        "fixture-postgres",
        "127.0.0.1:15432->5432/tcp",
        "{\"Command\":\"docker-entrypoint.sh postgres\",\"Image\":\"postgres:16.3\",\"Names\":\"fixture-postgres\",\"Ports\":\"127.0.0.1:15432->5432/tcp\"}",
        false)]
    [InlineData(
        "MySQL",
        null,
        "fixture-mysql",
        "127.0.0.1:13306->3306/tcp",
        "{\"Command\":\"docker-entrypoint.sh mysqld\",\"Image\":\"mysql:latest\",\"Names\":\"fixture-mysql\",\"Ports\":\"127.0.0.1:13306->3306/tcp\"}",
        true)]
    [InlineData(
        "MariaDB",
        "11.4",
        "fixture-mariadb",
        "127.0.0.1:13307->3306/tcp",
        "{\"Command\":\"mariadbd\",\"Image\":\"docker.io/library/mariadb:11.4\",\"Names\":\"fixture-mariadb\",\"Ports\":\"127.0.0.1:13307->3306/tcp\"}",
        false)]
    public void Detects_supported_container_databases_without_trusting_latest(
        string product,
        string? version,
        string containerName,
        string portEvidence,
        string evidence,
        bool requiresUserConfirmation)
    {
        var candidates = new HostDatabaseDiscovery().Detect(LoadFixture("linux-container-databases.txt"));

        var candidate = Assert.Single(candidates, item => item.Product == product);

        Assert.Equal(version, candidate.Version);
        Assert.Equal(DatabaseInstallationType.Container, candidate.InstallationType);
        Assert.Equal(containerName, candidate.InstanceName);
        Assert.Equal(portEvidence, candidate.PortEvidence);
        Assert.Equal(evidence, candidate.Evidence);
        Assert.Equal(requiresUserConfirmation, candidate.RequiresUserConfirmation);
        Assert.InRange(candidate.Confidence, 0.0, 1.0);
    }

    [Theory]
    [InlineData("postgres", "5432/tcp", "PostgreSQL")]
    [InlineData("mysql:latest", "0.0.0.0:33060->3306/tcp", "MySQL")]
    [InlineData("mariadb", "3306/tcp", "MariaDB")]
    public void Missing_or_latest_image_tags_require_confirmation_and_ports_do_not_supply_versions(
        string image,
        string ports,
        string product)
    {
        var output = Successful(
            DockerCommandId,
            ContainerLine(image, "fixture-unknown-version", ports));

        var candidate = Assert.Single(new HostDatabaseDiscovery().Detect(new[] { output }));

        Assert.Equal(product, candidate.Product);
        Assert.Null(candidate.Version);
        Assert.Equal(DatabaseInstallationType.Container, candidate.InstallationType);
        Assert.Equal("fixture-unknown-version", candidate.InstanceName);
        Assert.Equal(ports, candidate.PortEvidence);
        Assert.Equal(ContainerLine(image, "fixture-unknown-version", ports), candidate.Evidence);
        Assert.True(candidate.RequiresUserConfirmation);
    }

    [Fact]
    public void Multiple_instances_of_one_product_are_preserved_as_a_confirmation_conflict()
    {
        var output = Successful(
            DockerCommandId,
            string.Join(
                "\n",
                ContainerLine("postgres:15", "fixture-postgres-a", "15432->5432/tcp"),
                ContainerLine("postgres:16", "fixture-postgres-b", "25432->5432/tcp")));

        var candidates = new HostDatabaseDiscovery()
            .Detect(new[] { output })
            .Where(candidate => candidate.Product == "PostgreSQL")
            .ToArray();

        Assert.Equal(2, candidates.Length);
        Assert.All(candidates, candidate => Assert.True(candidate.RequiresUserConfirmation));
        Assert.All(candidates, candidate => Assert.Equal(DatabaseInstallationType.Container, candidate.InstallationType));
        Assert.Equal(
            new[] { "fixture-postgres-a", "fixture-postgres-b" },
            candidates.Select(candidate => candidate.InstanceName).OrderBy(name => name, StringComparer.Ordinal));
        Assert.Equal(
            new[] { "15", "16" },
            candidates.Select(candidate => candidate.Version).OrderBy(version => version, StringComparer.Ordinal));
        Assert.Equal(
            new[] { "15432->5432/tcp", "25432->5432/tcp" },
            candidates.Select(candidate => candidate.PortEvidence).OrderBy(ports => ports, StringComparer.Ordinal));
    }

    [Fact]
    public void Failed_optional_docker_and_podman_outputs_are_ignored()
    {
        var processLine = " 1042 postgres-15 /usr/lib/postgresql/15/bin/postgres -D /srv/fixture";
        var outputs = new[]
        {
            Successful(ProcessCommandId, processLine),
            Failed(DockerCommandId, ContainerLine("mysql:8.4", "must-not-appear", "3306/tcp")),
            Failed(PodmanCommandId, ContainerLine("mariadb:11.4", "must-not-appear", "3306/tcp"))
        };

        var candidate = Assert.Single(new HostDatabaseDiscovery().Detect(outputs));

        Assert.Equal("PostgreSQL", candidate.Product);
        Assert.Equal(processLine, candidate.Evidence);
    }

    [Fact]
    public void Legacy_or_unknown_command_ids_cannot_trigger_database_detection()
    {
        var output = Successful(
            "linux-docker-containers",
            ContainerLine("postgres:16", "must-not-appear", "5432/tcp"));

        Assert.Empty(new HostDatabaseDiscovery().Detect(new[] { output }));
    }

    [Fact]
    public void Multiple_native_process_instances_are_preserved_and_require_confirmation()
    {
        var outputs = new[]
        {
            Successful(
                ProcessCommandId,
                string.Join(
                    "\n",
                    " 1042 postgres-15 /usr/lib/postgresql/15/bin/postgres -D /srv/postgres-15",
                    " 1043 postgres-16 /usr/lib/postgresql/16/bin/postgres -D /srv/postgres-16")),
            Successful(
                ServiceCommandId,
                "postgresql.service loaded active running PostgreSQL database server")
        };

        var candidates = new HostDatabaseDiscovery().Detect(outputs);

        Assert.Equal(2, candidates.Count);
        Assert.Equal(new[] { "15", "16" }, candidates.Select(candidate => candidate.Version).OrderBy(value => value));
        Assert.All(candidates, candidate => Assert.True(candidate.RequiresUserConfirmation));
    }

    [Fact]
    public void Services_not_explicitly_loaded_active_and_running_are_ignored()
    {
        var output = Successful(
            ServiceCommandId,
            "mysql.service loaded inactive dead MySQL Community Server");

        Assert.Empty(new HostDatabaseDiscovery().Detect(new[] { output }));
    }

    [Theory]
    [InlineData("{\"Image\":\"postgres:16\",\"Image\":\"mysql:8\",\"Names\":\"duplicate\",\"Ports\":\"5432/tcp\"}")]
    [InlineData("{\"Image\":\"postgres:16\",\"Names\":\"trailing\",\"Ports\":\"5432/tcp\"} {}")]
    [InlineData("{\"Image\":\"postgres:16\",\"Names\":\"bad\\u0001name\",\"Ports\":\"5432/tcp\"}")]
    public void Malformed_or_control_character_container_json_is_ignored(string line)
    {
        var output = Successful(DockerCommandId, line);

        Assert.Empty(new HostDatabaseDiscovery().Detect(new[] { output }));
    }

    [Fact]
    public void Process_credentials_are_redacted_from_candidate_evidence()
    {
        var output = Successful(
            ProcessCommandId,
            " 2051 mysqld-8.0 /usr/sbin/mysqld-8.0 --user=audit --password=customer-secret");

        var candidate = Assert.Single(new HostDatabaseDiscovery().Detect(new[] { output }));

        Assert.DoesNotContain("customer-secret", candidate.Evidence, StringComparison.Ordinal);
        Assert.Contains("--password=***", candidate.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Discovery_results_and_candidates_are_immutable_snapshots()
    {
        var outputs = LoadFixture("linux-native-databases.txt").ToList();
        var results = new HostDatabaseDiscovery().Detect(outputs);
        outputs.Clear();

        var mutableView = Assert.IsAssignableFrom<IList<DatabaseInstanceCandidate>>(results);

        Assert.Equal(3, results.Count);
        Assert.Throws<NotSupportedException>(() => mutableView.RemoveAt(0));
        Assert.All(
            typeof(DatabaseInstanceCandidate).GetProperties(),
            property => Assert.Null(property.SetMethod));
    }

    private static IReadOnlyList<CommandOutput> LoadFixture(string fileName)
    {
        var path = FindFixture(fileName);
        var outputs = new List<CommandOutput>();
        string? commandId = null;
        var lines = new List<string>();

        foreach (var line in File.ReadLines(path))
        {
            const string marker = "# command: ";
            if (line.StartsWith(marker, StringComparison.Ordinal))
            {
                AddFixtureOutput(outputs, commandId, lines);
                commandId = line.Substring(marker.Length);
                lines.Clear();
                continue;
            }

            lines.Add(line);
        }

        AddFixtureOutput(outputs, commandId, lines);
        return outputs.AsReadOnly();
    }

    private static void AddFixtureOutput(
        ICollection<CommandOutput> outputs,
        string? commandId,
        IReadOnlyCollection<string> lines)
    {
        if (commandId == null)
        {
            Assert.Empty(lines);
            return;
        }

        outputs.Add(Successful(commandId, string.Join("\n", lines)));
    }

    private static string FindFixture(string fileName)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "tests", "fixtures", "detection", fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("Detection fixture was not found.", fileName);
    }

    private static CommandOutput Successful(string commandId, string standardOutput)
    {
        var timestamp = new DateTimeOffset(2026, 7, 17, 8, 0, 0, TimeSpan.Zero);
        return new CommandOutput(
            commandId,
            standardOutput,
            string.Empty,
            0,
            RemoteExecutionOutcome.Succeeded,
            null,
            timestamp,
            timestamp.AddSeconds(1));
    }

    private static CommandOutput Failed(string commandId, string standardOutput)
    {
        var timestamp = new DateTimeOffset(2026, 7, 17, 8, 0, 0, TimeSpan.Zero);
        return new CommandOutput(
            commandId,
            standardOutput,
            "optional container runtime unavailable",
            127,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.ProcessFailed,
            timestamp,
            timestamp.AddSeconds(1));
    }

    private static string ContainerLine(string image, string name, string ports)
    {
        return "{\"Command\":\"fixture\",\"Image\":\"" + image
            + "\",\"Names\":\"" + name + "\",\"Ports\":\"" + ports + "\"}";
    }
}
