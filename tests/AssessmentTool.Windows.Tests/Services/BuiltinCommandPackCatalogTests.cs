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

            Assert.Equal("generic-linux", pack.Id);
            Assert.Equal(
                new[] { "generic-linux-uname-a", "generic-linux-os-release" },
                identification.Select(command => command.Id));
            Assert.Equal(
                new[] { "generic-linux-hostname" },
                collection.Select(command => command.Id));
            Assert.Equal(
                pack.Commands.Select(command => command.Id).OrderBy(id => id),
                identification.Concat(collection).Select(command => command.Id).OrderBy(id => id));
            Assert.All(pack.Commands, command => Assert.True(command.IsEligibleForAutomaticExecution));
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
            Assert.Equal(3, pack.Commands.Count);
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
