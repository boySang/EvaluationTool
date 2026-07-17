using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Security;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AssessmentTool.Core.Tests.Commands;

public sealed class DatabaseHostDiscoveryCommandPackTests
{
    private static readonly IReadOnlyList<string> ExpectedCommandIds = new[]
    {
        "database-host-discovery-linux-processes",
        "database-host-discovery-linux-services",
        "database-host-discovery-linux-docker-containers",
        "database-host-discovery-linux-podman-containers"
    };

    private static readonly IReadOnlyList<string> ExpectedCommands = new[]
    {
        "ps -eo pid,comm",
        "systemctl list-units --type=service --state=running --no-pager",
        "docker ps --no-trunc --format '{\"Image\":{{json .Image}},\"Names\":{{json .Names}},\"Ports\":{{json .Ports}}}'",
        "podman ps --no-trunc --format '{\"Image\":{{json .Image}},\"Names\":{{json .Names}},\"Ports\":{{json .Ports}}}'"
    };

    [Fact]
    public void Pack_contains_only_the_four_planned_read_only_commands()
    {
        var commands = ReadCommands();

        Assert.Equal(ExpectedCommandIds, commands.Select(command => command.Value<string>("id")));
        Assert.Equal(ExpectedCommands, commands.Select(CommandText));
        Assert.All(commands, command => Assert.True(command.Value<bool>("isReadOnly")));
        Assert.All(commands, command => Assert.Equal("Verified", command.Value<string>("verificationStatus")));
    }

    [Fact]
    public void Process_discovery_is_required_while_platform_specific_sources_are_optional()
    {
        var commands = ReadCommands().ToDictionary(CommandText, StringComparer.Ordinal);

        Assert.Null(commands[ExpectedCommands[0]]["optional"]);
        Assert.True(commands[ExpectedCommands[1]].Value<bool>("optional"));
        Assert.True(commands[ExpectedCommands[2]].Value<bool>("optional"));
        Assert.True(commands[ExpectedCommands[3]].Value<bool>("optional"));
    }

    [Fact]
    public void Commands_reference_their_official_documentation()
    {
        var expectedSources = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [ExpectedCommands[0]] = "https://gitlab.com/procps-ng/procps/-/blob/master/man/ps.1",
            [ExpectedCommands[1]] = "https://www.freedesktop.org/software/systemd/man/latest/systemctl.html",
            [ExpectedCommands[2]] = "https://docs.docker.com/reference/cli/docker/container/ls",
            [ExpectedCommands[3]] = "https://docs.podman.io/en/latest/markdown/podman-ps.1.html"
        };

        Assert.All(
            ReadCommands(),
            command => Assert.Equal(expectedSources[CommandText(command)], command.Value<string>("officialSource")));
    }

    [Fact]
    public void Pack_excludes_exec_scanning_file_searches_and_container_lifecycle_commands()
    {
        var commandTexts = ReadCommands().Select(CommandText).ToArray();
        var forbiddenFragments = new[]
        {
            " exec ",
            " nmap ",
            " find ",
            " locate ",
            " run ",
            " start ",
            " stop ",
            " restart ",
            " rm "
        };

        Assert.All(commandTexts, commandText =>
        {
            var padded = " " + commandText.ToLowerInvariant() + " ";
            Assert.DoesNotContain(forbiddenFragments, padded.Contains);
        });
    }

    [Fact]
    public void Discovery_commands_do_not_collect_process_arguments_or_unbounded_container_metadata()
    {
        var commandTexts = ReadCommands().Select(CommandText).ToArray();

        Assert.DoesNotContain(commandTexts, command => command.Contains("args", StringComparison.Ordinal));
        Assert.DoesNotContain(commandTexts, command => command.Contains("{{json .}}", StringComparison.Ordinal));
        Assert.All(
            commandTexts.Skip(2),
            command =>
            {
                Assert.Contains(".Image", command, StringComparison.Ordinal);
                Assert.Contains(".Names", command, StringComparison.Ordinal);
                Assert.Contains(".Ports", command, StringComparison.Ordinal);
            });
    }

    [Fact]
    public void Schema_can_express_optional_commands()
    {
        var root = FindRepositoryRoot();
        var schema = JObject.Parse(File.ReadAllText(Path.Combine(
            root,
            "command-packs",
            "schema",
            "command-pack.schema.json")));
        var optionalProperty = schema.SelectToken("$defs.command.properties.optional");

        Assert.NotNull(optionalProperty);
        Assert.Equal("boolean", optionalProperty!["type"]?.Value<string>());
    }

    [Fact]
    public void Loader_accepts_the_pack_and_preserves_optional_command_semantics()
    {
        var packBytes = File.ReadAllBytes(PackPath());
        var pack = new CommandPackLoader().Load(packBytes, Sha256(packBytes));

        Assert.Equal("database-host-discovery-linux", pack.Id);
        Assert.Equal(
            new[] { false, true, true, true },
            pack.Commands.Select(command => command.IsOptional));
        Assert.All(pack.Commands, command => Assert.True(new CommandSafetyPolicy().Validate(command).Allowed));
    }

    private static JArray ReadCommands()
    {
        var document = JObject.Parse(File.ReadAllText(PackPath()));
        return Assert.IsType<JArray>(document["commands"]);
    }

    private static string CommandText(JToken command)
    {
        return Assert.IsType<JObject>(command).Value<string>("commandText")
            ?? throw new InvalidDataException("命令文本不能为空。");
    }

    private static string PackPath()
    {
        return Path.Combine(
            FindRepositoryRoot(),
            "command-packs",
            "builtin",
            "database-host-discovery-linux.json");
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current != null)
        {
            if (File.Exists(Path.Combine(current.FullName, "AssessmentTool.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("找不到仓库根目录。");
    }

    private static string Sha256(byte[] bytes)
    {
        using var sha256 = SHA256.Create();
        return string.Concat(sha256.ComputeHash(bytes).Select(value => value.ToString("x2")));
    }
}
