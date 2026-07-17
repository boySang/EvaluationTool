using System;
using AssessmentTool.Core.Domain;
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

    [Theory]
    [InlineData(@"C:\测评证据\设备甲\原始输出.txt", "/select,\"C:\\测评证据\\设备甲\\原始输出.txt\"")]
    [InlineData(@"C:\Evidence Folder\page 1.png", "/select,\"C:\\Evidence Folder\\page 1.png\"")]
    public void Evidence_file_path_is_serialized_for_explorer_select(string path, string expected)
    {
        Assert.Equal(expected, ProjectEvidenceFileLocator.SerializeSelectArgument(path));
    }

    [Fact]
    public void Evidence_file_locator_requires_exactly_one_current_project_index_record()
    {
        var projectId = ProjectId.New();
        var record = new EvidenceFileRecord(
            projectId,
            DeviceId.New(),
            @"设备甲\原始输出.txt",
            new string('a', 64),
            EvidenceFileKind.RawOutput,
            0,
            DateTimeOffset.UtcNow);

        Assert.Equal(
            @"设备甲\原始输出.txt",
            ProjectEvidenceFileLocator.RequireUniqueIndexedPath(
                projectId,
                new[] { record },
                @"设备甲/原始输出.txt"));
        Assert.Throws<System.IO.InvalidDataException>(() =>
            ProjectEvidenceFileLocator.RequireUniqueIndexedPath(
                projectId,
                new[] { record, record },
                record.RelativePath));
        Assert.Throws<System.IO.InvalidDataException>(() =>
            ProjectEvidenceFileLocator.RequireUniqueIndexedPath(
                projectId,
                new[]
                {
                    new EvidenceFileRecord(
                        ProjectId.New(),
                        DeviceId.New(),
                        record.RelativePath,
                        record.Sha256,
                        record.Kind,
                        record.Ordinal,
                        record.CreatedAt)
                },
                record.RelativePath));
    }
}
