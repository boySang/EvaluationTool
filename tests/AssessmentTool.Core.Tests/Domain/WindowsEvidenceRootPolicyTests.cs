using System;
using System.IO;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Domain;

public sealed class WindowsEvidenceRootPolicyTests
{
    [Theory]
    [InlineData(@"C:\", @"C:\")]
    [InlineData(@"C:\测评证据\", @"C:\测评证据")]
    [InlineData(@"\\server\share\", @"\\server\share")]
    public void Normalize_preserves_drive_root_and_trims_non_root_separator(string input, string expected)
    {
        Assert.Equal(expected, WindowsEvidenceRootPolicy.Normalize(input, nameof(input)));
    }

    [Theory]
    [InlineData("relative")]
    [InlineData(@"C:relative")]
    [InlineData(@"\\?\C:\evidence")]
    [InlineData(@"\\server")]
    public void Normalize_rejects_ambiguous_or_device_paths(string input)
    {
        Assert.Throws<ArgumentException>(() => WindowsEvidenceRootPolicy.Normalize(input, nameof(input)));
    }

    [Fact]
    public void Resolve_contained_path_handles_drive_root_without_changing_drive_semantics()
    {
        var path = WindowsEvidenceRootPolicy.ResolveContainedPath(
            @"C:\",
            @"项目\设备\原始输出.txt",
            "path");

        Assert.Equal(@"C:\项目\设备\原始输出.txt", path);
        Assert.True(Path.IsPathRooted(path));
    }
}
