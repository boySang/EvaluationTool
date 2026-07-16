using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using AssessmentTool.Windows.Evidence;
using Xunit;

namespace AssessmentTool.Windows.Tests.Evidence;

public sealed class WpfEvidenceRendererTests
{
    private const int PageWidth = 1400;
    private const int PageHeight = 900;

    [Fact]
    public void Long_output_creates_numbered_pages_with_matching_sha256_values()
    {
        RunInSta(() =>
        {
            using (var folder = new TemporaryFolder())
            {
                var renderer = new WpfEvidenceRenderer(PageWidth, PageHeight);

                var files = renderer.Render(LongFixtureOutput(300), CreateHeader(), folder.Path);

                Assert.True(files.Count > 1);
                Assert.Equal("证据_001.png", Path.GetFileName(files[0].Path));
                Assert.Equal(
                    Enumerable.Range(1, files.Count).Select(page => $"证据_{page:000}.png"),
                    files.Select(file => Path.GetFileName(file.Path)));
                Assert.All(files, file => Assert.Equal(ComputeSha256(file.Path), file.Sha256));
            }
        });
    }

    [Fact]
    public void Header_contains_project_device_check_command_timestamp_and_page_number()
    {
        RunInSta(() =>
        {
            using (var folder = new TemporaryFolder())
            {
                var baseline = RenderFirstPage(folder.CreateSubdirectory("baseline"), CreateHeader());
                var variants = new[]
                {
                    CreateHeader(projectName: "项目乙"),
                    CreateHeader(deviceName: "核心交换机乙"),
                    CreateHeader(checkItem: "安全审计乙"),
                    CreateHeader(command: "show users"),
                    CreateHeader(executedAt: new DateTimeOffset(2026, 7, 16, 11, 22, 33, TimeSpan.FromHours(8)))
                };

                for (var index = 0; index < variants.Length; index++)
                {
                    var variant = RenderFirstPage(folder.CreateSubdirectory("variant-" + index), variants[index]);
                    Assert.NotEqual(HeaderPixelHash(baseline), HeaderPixelHash(variant));
                }

                var pages = new WpfEvidenceRenderer(PageWidth, PageHeight).Render(
                    LongFixtureOutput(300),
                    CreateHeader(),
                    folder.CreateSubdirectory("pages"));

                Assert.True(pages.Count > 1);
                Assert.NotEqual(HeaderPixelHash(pages[0].Path), HeaderPixelHash(pages[1].Path));
            }
        });
    }

    [Fact]
    public void Chinese_crlf_and_long_lines_are_normalized_wrapped_and_not_truncated()
    {
        RunInSta(() =>
        {
            using (var folder = new TemporaryFolder())
            {
                var renderer = new WpfEvidenceRenderer(PageWidth, PageHeight);
                var longChineseLine = string.Concat(Enumerable.Repeat("中文配置项值", 2500));
                var crlfOutput = "设备输出\r\n" + longChineseLine + "\r\n末尾甲";
                var lfOutput = crlfOutput.Replace("\r\n", "\n");
                var changedSuffixOutput = lfOutput.Substring(0, lfOutput.Length - 1) + "乙";

                var crlfPages = renderer.Render(crlfOutput, CreateHeader(), folder.CreateSubdirectory("crlf"));
                var lfPages = renderer.Render(lfOutput, CreateHeader(), folder.CreateSubdirectory("lf"));
                var changedSuffixPages = renderer.Render(
                    changedSuffixOutput,
                    CreateHeader(),
                    folder.CreateSubdirectory("changed-suffix"));

                Assert.True(crlfPages.Count > 1);
                Assert.Equal(crlfPages.Select(page => page.Sha256), lfPages.Select(page => page.Sha256));
                Assert.Equal(lfPages.Count, changedSuffixPages.Count);
                Assert.Equal(
                    lfPages.Take(lfPages.Count - 1).Select(page => page.Sha256),
                    changedSuffixPages.Take(changedSuffixPages.Count - 1).Select(page => page.Sha256));
                Assert.NotEqual(lfPages.Last().Sha256, changedSuffixPages.Last().Sha256);
            }
        });
    }

    [Fact]
    public void Rendering_is_headless_deterministic_and_does_not_capture_the_desktop()
    {
        RunInSta(() =>
        {
            using (var folder = new TemporaryFolder())
            {
                var renderer = new WpfEvidenceRenderer(PageWidth, PageHeight);
                var first = renderer.Render("actual terminal output", CreateHeader(), folder.CreateSubdirectory("first"));
                var second = renderer.Render("actual terminal output", CreateHeader(), folder.CreateSubdirectory("second"));

                Assert.Equal(first.Select(page => page.Sha256), second.Select(page => page.Sha256));
                Assert.Equal(File.ReadAllBytes(first[0].Path), File.ReadAllBytes(second[0].Path));
            }
        });
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \r\n\t")]
    public void Empty_output_is_rejected(string? output)
    {
        RunInSta(() =>
        {
            using (var folder = new TemporaryFolder())
            {
                var renderer = new WpfEvidenceRenderer(PageWidth, PageHeight);

                Assert.Throws<ArgumentException>(() => renderer.Render(output!, CreateHeader(), folder.Path));
                Assert.Empty(Directory.GetFiles(folder.Path));
            }
        });
    }

    [Fact]
    public void Every_page_has_the_configured_fixed_pixel_size()
    {
        RunInSta(() =>
        {
            using (var folder = new TemporaryFolder())
            {
                var files = new WpfEvidenceRenderer(PageWidth, PageHeight).Render(
                    LongFixtureOutput(300),
                    CreateHeader(),
                    folder.Path);

                Assert.All(files, file =>
                {
                    var bitmap = LoadBitmap(file.Path);
                    Assert.Equal(PageWidth, bitmap.PixelWidth);
                    Assert.Equal(PageHeight, bitmap.PixelHeight);
                });
            }
        });
    }

    [Fact]
    public void Header_that_cannot_fit_is_rejected_without_creating_partial_pages()
    {
        RunInSta(() =>
        {
            using (var folder = new TemporaryFolder())
            {
                var header = CreateHeader(command: new string('命', 1000));
                var renderer = new WpfEvidenceRenderer(PageWidth, PageHeight);

                Assert.Throws<ArgumentException>(() => renderer.Render("actual output", header, folder.Path));
                Assert.Empty(Directory.GetFiles(folder.Path));
            }
        });
    }

    private static string RenderFirstPage(string outputDirectory, EvidenceHeader header)
    {
        return new WpfEvidenceRenderer(PageWidth, PageHeight)
            .Render("actual terminal output", header, outputDirectory)[0]
            .Path;
    }

    private static EvidenceHeader CreateHeader(
        string projectName = "项目甲",
        string deviceName = "核心交换机甲",
        string checkItem = "身份鉴别甲",
        string command = "show running-config",
        DateTimeOffset? executedAt = null)
    {
        return new EvidenceHeader(
            projectName,
            deviceName,
            checkItem,
            command,
            executedAt ?? new DateTimeOffset(2026, 7, 16, 10, 20, 30, TimeSpan.FromHours(8)));
    }

    private static string LongFixtureOutput(int lineCount)
    {
        return string.Join("\r\n", Enumerable.Range(1, lineCount).Select(line =>
            $"{line:0000} | interface GigabitEthernet0/{line % 48} | 状态 up | 只读采集输出"));
    }

    private static string HeaderPixelHash(string path)
    {
        var bitmap = LoadBitmap(path);
        const int headerHeight = 240;
        var stride = bitmap.PixelWidth * 4;
        var pixels = new byte[stride * headerHeight];
        bitmap.CopyPixels(new System.Windows.Int32Rect(0, 0, bitmap.PixelWidth, headerHeight), pixels, stride, 0);
        using (var sha256 = SHA256.Create())
        {
            return ToLowerHex(sha256.ComputeHash(pixels));
        }
    }

    private static BitmapSource LoadBitmap(string path)
    {
        using (var stream = File.OpenRead(path))
        {
            var frame = BitmapFrame.Create(stream, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
            var converted = new FormatConvertedBitmap(frame, PixelFormats.Bgra32, null, 0);
            converted.Freeze();
            return converted;
        }
    }

    private static string ComputeSha256(string path)
    {
        using (var stream = File.OpenRead(path))
        using (var sha256 = SHA256.Create())
        {
            return ToLowerHex(sha256.ComputeHash(stream));
        }
    }

    private static string ToLowerHex(IEnumerable<byte> bytes)
    {
        return string.Concat(bytes.Select(value => value.ToString("x2")));
    }

    private static void RunInSta(Action action)
    {
        ExceptionDispatchInfo? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception exception)
            {
                failure = ExceptionDispatchInfo.Capture(exception);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        if (!thread.Join(TimeSpan.FromSeconds(30)))
        {
            throw new TimeoutException("WPF 证据渲染测试超过 30 秒。");
        }
        failure?.Throw();
    }

    private sealed class TemporaryFolder : IDisposable
    {
        public TemporaryFolder()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AssessmentTool-WpfEvidence-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public string CreateSubdirectory(string name)
        {
            var path = System.IO.Path.Combine(Path, name);
            Directory.CreateDirectory(path);
            return path;
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
