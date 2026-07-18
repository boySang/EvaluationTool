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
        Assert.Contains("#define AppExeName \"EvaluationTool.exe\"", source);
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

    [Fact]
    public void Native_startup_checker_blocks_unsupported_or_damaged_packages_before_wpf_starts()
    {
        var root = FindRepositoryRoot();
        var decisionSource = File.ReadAllText(Path.Combine(
            root,
            "src",
            "AssessmentTool.Bootstrapper",
            "BootstrapDecision.cpp"));
        var launcherSource = File.ReadAllText(Path.Combine(
            root,
            "src",
            "AssessmentTool.Bootstrapper",
            "main.cpp"));
        var workflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "windows-ci.yml"));

        Assert.True(
            decisionSource.IndexOf("!input.IsSupportedWindows", StringComparison.Ordinal)
            < decisionSource.IndexOf("!input.HasDotNet48", StringComparison.Ordinal));
        Assert.Contains("DotNet48Release = 528040", launcherSource);
        Assert.Contains("ASSESSMENTTOOL_APP_SHA256", launcherSource);
        Assert.Contains("FILE_ATTRIBUTE_REPARSE_POINT", launcherSource);
        Assert.Contains("--diagnose-exit-code", launcherSource);
        Assert.DoesNotContain("plink.exe", launcherSource, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Build and test native startup checker", workflow);
        Assert.Contains("BootstrapDecisionTests.exe", workflow);
        Assert.Contains("Missing manifest diagnostic", workflow);
        Assert.Contains("Modified application diagnostic", workflow);
        Assert.Contains("Packaged startup checker did not launch", workflow);
        Assert.Contains("EvaluationTool-ui-screenshots-windows", workflow);
        Assert.Contains("01-home-dashboard.png", workflow);
        Assert.Contains("02-device-list.png", workflow);
        Assert.Contains("03-add-device.png", workflow);
        Assert.Contains("PrintWindow", workflow);

        var measureIndex = workflow.IndexOf("Measure portable package size", StringComparison.Ordinal);
        var manifestIndex = workflow.IndexOf(
            "Generate and verify Release integrity manifest",
            StringComparison.Ordinal);
        var diagnosticIndex = workflow.IndexOf(
            "Test startup checker package integrity decisions",
            StringComparison.Ordinal);
        Assert.True(measureIndex >= 0 && manifestIndex > measureIndex && diagnosticIndex > manifestIndex);
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
