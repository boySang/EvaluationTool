using System;
using System.IO;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class ReleasePackagingContractTests
{
    [Fact]
    public void Installer_is_per_user_x64_and_checks_dotnet_before_copying_files()
    {
        var source = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "installer", "AssessmentTool.iss"));

        Assert.Contains("PrivilegesRequired=lowest", source);
        Assert.DoesNotContain("PrivilegesRequired=admin", source);
        Assert.Contains("DefaultDirName={localappdata}\\Programs\\EvaluationTool", source);
        Assert.Contains("ArchitecturesAllowed=x64compatible", source);
        Assert.Contains("MinVersion=10.0.10240", source);
        Assert.Contains("DotNet48Release = 528040", source);
        Assert.Contains("dotnet.microsoft.com/download/dotnet-framework/net48", source);
        Assert.Contains("MessagesFile: \"compiler:Default.isl\"", source);
        Assert.Contains("Source: \"{#ReleaseRoot}\\*\"", source);
        Assert.DoesNotContain("[UninstallDelete]", source);
    }

    [Fact]
    public void Windows_pipeline_packages_manifest_then_tests_install_and_data_preserving_uninstall()
    {
        var source = File.ReadAllText(Path.Combine(
            FindRepositoryRoot(),
            ".github",
            "workflows",
            "windows-ci.yml"));
        var manifestIndex = source.IndexOf(
            "Generate and verify Release integrity manifest",
            StringComparison.Ordinal);
        var installerIndex = source.IndexOf(
            "Build per-user Windows installer",
            StringComparison.Ordinal);

        Assert.True(manifestIndex >= 0 && installerIndex > manifestIndex);
        Assert.Contains("Smoke test installer and data-preserving uninstall", source);
        Assert.Contains("Installed application did not display its main window", source);
        Assert.Contains("installer-preservation-sentinel.txt", source);
        Assert.Contains("Uninstaller removed current-user EvaluationTool project data", source);
        Assert.Contains("EvaluationTool-Installer-windows-x64", source);
        Assert.Contains("-PackageKind installer-windows-x64", source);
        Assert.Contains("-TargetMaximumMegabytes 60", source);
        Assert.Contains("steps.packaged_startup.outcome == 'failure'", source);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "installer", "AssessmentTool.iss"))
                && File.Exists(Path.Combine(directory.FullName, "AssessmentTool.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Unable to locate the EvaluationTool repository root.");
    }
}
