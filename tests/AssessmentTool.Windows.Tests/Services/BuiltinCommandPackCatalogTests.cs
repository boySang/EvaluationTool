using System;
using System.IO;
using System.Linq;
using System.Text;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Commands;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class BuiltinCommandPackCatalogTests
{
    [Fact]
    public void LoadGenericLinux_uses_verified_release_file_and_returns_explicit_command_groups()
    {
        var releaseDirectory = CreateReleaseDirectory();
        try
        {
            CopyRepositoryPackToReleaseDirectory(releaseDirectory);
            var catalog = new BuiltinCommandPackCatalog(releaseDirectory);

            var pack = catalog.LoadGenericLinux();
            var identification = catalog.SelectGenericLinuxIdentificationCommands(pack);
            var collection = catalog.SelectGenericLinuxCollectionCommands(pack);
            var collectionPack = catalog.CreateGenericLinuxCollectionPack(pack);

            Assert.Equal("generic-linux", pack.Id);
            Assert.Equal(
                new[] { "generic-linux-uname-a", "generic-linux-os-release" },
                identification.Select(command => command.Id));
            Assert.Equal(
                new[] { "generic-linux-hostname", "generic-linux-login-defs" },
                collection.Select(command => command.Id));
            Assert.Equal(
                pack.Commands.Select(command => command.Id).OrderBy(id => id),
                identification.Concat(collection).Select(command => command.Id).OrderBy(id => id));
            Assert.All(pack.Commands, command => Assert.True(command.IsEligibleForAutomaticExecution));
            Assert.Equal(
                new[] { "generic-linux-hostname", "generic-linux-login-defs" },
                collectionPack.Commands.Select(command => command.Id));
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public void LoadGenericLinux_falls_back_to_fixed_embedded_resource_when_release_file_is_absent()
    {
        var releaseDirectory = CreateReleaseDirectory();
        try
        {
            var pack = new BuiltinCommandPackCatalog(releaseDirectory).LoadGenericLinux();

            Assert.Equal("generic-linux", pack.Id);
            Assert.Equal(4, pack.Commands.Count);
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public void LoadGenericLinux_rejects_tampered_release_file_without_falling_back_to_resource()
    {
        var releaseDirectory = CreateReleaseDirectory();
        try
        {
            var packPath = GetReleasePackPath(releaseDirectory);
            Directory.CreateDirectory(Path.GetDirectoryName(packPath)!);
            File.WriteAllText(packPath, "{\"id\":\"tampered\"}", new UTF8Encoding(false));

            var error = Assert.Throws<CommandPackException>(() =>
                new BuiltinCommandPackCatalog(releaseDirectory).LoadGenericLinux());

            Assert.Contains("SHA-256", error.Message);
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public void Published_generic_linux_file_is_configured_as_content_and_embedded_resource()
    {
        var projectPath = Path.Combine(
            FindRepositoryRoot(),
            "src",
            "AssessmentTool.App",
            "AssessmentTool.App.csproj");
        var project = File.ReadAllText(projectPath);

        Assert.Contains("Link=\"command-packs/builtin/generic-linux.json\"", project);
        Assert.Contains("CopyToOutputDirectory=\"PreserveNewest\"", project);
        Assert.Contains("LogicalName=\"AssessmentTool.App.CommandPacks.Builtin.GenericLinux.json\"", project);
        Assert.Contains("Link=\"command-packs/builtin/database-host-discovery-linux.json\"", project);
        Assert.Contains("LogicalName=\"AssessmentTool.App.CommandPacks.Builtin.DatabaseHostDiscoveryLinux.json\"", project);
    }

    [Fact]
    public void LoadDatabaseHostDiscoveryLinux_uses_fixed_hash_layout_and_embedded_fallback()
    {
        var releaseDirectory = CreateReleaseDirectory();
        try
        {
            var pack = new BuiltinCommandPackCatalog(releaseDirectory).LoadDatabaseHostDiscoveryLinux();

            Assert.Equal("database-host-discovery-linux", pack.Id);
            Assert.Equal("1.1.0", pack.Version);
            Assert.Equal(
                new[]
                {
                    "database-host-discovery-linux-processes",
                    "database-host-discovery-linux-services",
                    "database-host-discovery-linux-docker-containers",
                    "database-host-discovery-linux-podman-containers"
                },
                pack.Commands.Select(command => command.Id));
            Assert.All(pack.Commands, command => Assert.True(command.IsEligibleForAutomaticExecution));
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    private static string CreateReleaseDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "EvaluationTool.BuiltinPacks", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void CopyRepositoryPackToReleaseDirectory(string releaseDirectory)
    {
        var source = Path.Combine(
            FindRepositoryRoot(),
            "command-packs",
            "builtin",
            "generic-linux.json");
        var destination = GetReleasePackPath(releaseDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(source, destination);
    }

    private static string GetReleasePackPath(string releaseDirectory)
    {
        return Path.Combine(releaseDirectory, "command-packs", "builtin", "generic-linux.json");
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "command-packs"))
                && Directory.Exists(Path.Combine(directory.FullName, "src")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Unable to locate repository root.");
    }
}
