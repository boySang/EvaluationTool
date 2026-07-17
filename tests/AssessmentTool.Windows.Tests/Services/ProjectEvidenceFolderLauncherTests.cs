using System;
using AssessmentTool.App.Services;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class ProjectEvidenceFolderLauncherTests
{
    [Theory]
    [InlineData(@"C:\测评证据", "\"C:\\测评证据\"")]
    [InlineData(@"C:\Evidence Folder\", "\"C:\\Evidence Folder\\\\\"")]
    [InlineData(@"\\server\share\项目", "\"\\\\server\\share\\项目\"")]
    public void Explorer_path_is_serialized_as_exactly_one_argument(string path, string expected)
    {
        Assert.Equal(expected, ProjectEvidenceFolderLauncher.SerializeArgument(path));
    }

    [Theory]
    [InlineData("C:\\Evidence\rnext")]
    [InlineData("C:\\Evidence\nnext")]
    [InlineData("C:\\Evidence\0next")]
    public void Explorer_path_rejects_command_line_control_characters(string path)
    {
        Assert.Throws<ArgumentException>(() => ProjectEvidenceFolderLauncher.SerializeArgument(path));
    }
}
