using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using AssessmentTool.Core.Evidence;
using Xunit;

namespace AssessmentTool.Core.Tests.Evidence;

public sealed class EvidencePathBuilderTests : IDisposable
{
    private static readonly DateTimeOffset FixedTime = new DateTimeOffset(2026, 7, 16, 9, 8, 7, TimeSpan.FromHours(8));
    private readonly string temporaryRoot = Path.Combine(Path.GetTempPath(), "assessment-tool-evidence-path-tests", Guid.NewGuid().ToString("N"));

    [Theory]
    [InlineData("设备:A/B\\C*?\"<D>|\u0001", "设备_A_B_C____D___")]
    [InlineData("正常中文名称", "正常中文名称")]
    public void SanitizeSegment_replaces_windows_invalid_characters(string input, string expected)
    {
        var value = Builder().SanitizeSegment(input);

        Assert.Equal(expected, value);
    }

    [Theory]
    [InlineData("CON", "_CON")]
    [InlineData("prn.txt", "_prn.txt")]
    [InlineData("COM1.log", "_COM1.log")]
    [InlineData("lpt9", "_lpt9")]
    [InlineData("CLOCK$", "_CLOCK$")]
    [InlineData("COM¹.txt", "_COM¹.txt")]
    public void SanitizeSegment_escapes_windows_reserved_device_names(string input, string expected)
    {
        var value = Builder().SanitizeSegment(input);

        Assert.Equal(expected, value);
    }

    [Theory]
    [InlineData("设备名称...   ", "设备名称")]
    [InlineData(". ", "_")]
    [InlineData("   ", "_")]
    public void SanitizeSegment_removes_trailing_dots_and_spaces_without_returning_an_empty_name(
        string input,
        string expected)
    {
        var value = Builder().SanitizeSegment(input);

        Assert.Equal(expected, value);
    }

    [Fact]
    public void SanitizeSegment_truncates_to_80_characters_and_appends_the_first_8_sha256_characters()
    {
        var input = new string('测', 100);
        var expectedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)))
            .ToLowerInvariant()
            .Substring(0, 8);

        var value = Builder().SanitizeSegment(input);

        Assert.Equal(80, value.Length);
        Assert.Equal(new string('测', 71) + "-" + expectedHash, value);
    }

    [Fact]
    public void CreateBatchDirectory_reserves_a_new_directory_for_repeated_execution_at_the_same_time()
    {
        var builder = Builder();

        var first = builder.CreateBatchDirectory("项目A", "设备A", "身份鉴别", FixedTime);
        var second = builder.CreateBatchDirectory("项目A", "设备A", "身份鉴别", FixedTime);

        Assert.NotEqual(first, second);
        Assert.True(Directory.Exists(first));
        Assert.True(Directory.Exists(second));
    }

    [Fact]
    public void CreateBatchDirectory_keeps_the_complete_batch_path_within_the_configured_limit()
    {
        const int maximumTotalPathLength = 240;
        var builder = new EvidencePathBuilder(temporaryRoot, maximumTotalPathLength);
        var longName = new string('长', 120);

        var path = builder.CreateBatchDirectory(longName, longName, longName, FixedTime);

        Assert.StartsWith(Path.GetFullPath(temporaryRoot) + Path.DirectorySeparatorChar, path, StringComparison.Ordinal);
        Assert.True(path.Length <= maximumTotalPathLength, $"实际路径长度为 {path.Length}：{path}");
        Assert.True(
            (path + Path.DirectorySeparatorChar + "执行记录.json.tmp-" + new string('0', 32)).Length <= maximumTotalPathLength,
            "路径预算必须为最终文件和原子写入临时后缀预留空间。");
        Assert.True(Directory.Exists(path));
    }

    [Fact]
    public void SanitizeSegment_replaces_percent_that_the_shared_windows_path_policy_rejects()
    {
        Assert.Equal("设备_25", Builder().SanitizeSegment("设备%25"));
    }

    public void Dispose()
    {
        if (Directory.Exists(temporaryRoot))
        {
            Directory.Delete(temporaryRoot, true);
        }
    }

    private EvidencePathBuilder Builder(int maximumTotalPathLength = 240)
    {
        return new EvidencePathBuilder(temporaryRoot, maximumTotalPathLength);
    }
}
