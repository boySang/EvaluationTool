using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace AssessmentTool.Windows.Evidence;

public sealed class EvidenceHeader
{
    public EvidenceHeader(
        string projectName,
        string deviceName,
        string checkItem,
        string command,
        DateTimeOffset executedAt)
    {
        ProjectName = Required(projectName, nameof(projectName));
        DeviceName = Required(deviceName, nameof(deviceName));
        CheckItem = Required(checkItem, nameof(checkItem));
        Command = Required(command, nameof(command));
        ExecutedAt = executedAt;
    }

    public string ProjectName { get; }
    public string DeviceName { get; }
    public string CheckItem { get; }
    public string Command { get; }
    public DateTimeOffset ExecutedAt { get; }

    private static string Required(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("证据页眉字段不能为空。", parameterName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException("证据页眉字段不能包含换行或其他控制字符。", parameterName);
        }

        return value;
    }
}

public sealed class RenderedEvidencePage
{
    internal RenderedEvidencePage(string path, string sha256)
    {
        Path = path;
        Sha256 = sha256;
    }

    public string Path { get; }
    public string Sha256 { get; }
}

public sealed class WpfEvidenceRenderer
{
    private const double Dpi = 96;
    private const double HeaderHeight = 240;
    private const double FooterHeight = 24;
    private const double HorizontalMargin = 36;
    private const double BodyLineHeight = 19;

    private readonly int pageWidth;
    private readonly int pageHeight;

    public WpfEvidenceRenderer(int pageWidth, int pageHeight)
    {
        if (pageWidth < 640)
        {
            throw new ArgumentOutOfRangeException(nameof(pageWidth), "证据图片宽度不能小于 640 像素。");
        }

        if (pageHeight < 480)
        {
            throw new ArgumentOutOfRangeException(nameof(pageHeight), "证据图片高度不能小于 480 像素。");
        }

        this.pageWidth = pageWidth;
        this.pageHeight = pageHeight;
    }

    public IReadOnlyList<RenderedEvidencePage> Render(
        string exactOutput,
        EvidenceHeader header,
        string outputDirectory)
    {
        if (string.IsNullOrWhiteSpace(exactOutput))
        {
            throw new ArgumentException("原始输出为空，不能生成证据截图。", nameof(exactOutput));
        }

        if (header == null)
        {
            throw new ArgumentNullException(nameof(header));
        }

        if (string.IsNullOrWhiteSpace(outputDirectory))
        {
            throw new ArgumentException("证据图片目录不能为空。", nameof(outputDirectory));
        }

        if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
        {
            throw new InvalidOperationException("WPF 证据渲染必须在 STA 线程运行。");
        }

        Directory.CreateDirectory(outputDirectory);
        EnsureHeaderFits(header);
        var displayLines = ProjectDisplayLines(NormalizeLineEndings(exactOutput));
        var availableHeight = pageHeight - HeaderHeight - FooterHeight;
        var linesPerPage = Math.Max(1, (int)Math.Floor(availableHeight / BodyLineHeight));
        var pageCount = (displayLines.Count + linesPerPage - 1) / linesPerPage;
        var digits = Math.Max(3, pageCount.ToString(CultureInfo.InvariantCulture).Length);
        var rendered = new List<RenderedEvidencePage>(pageCount);

        for (var pageIndex = 0; pageIndex < pageCount; pageIndex++)
        {
            var fileName = "证据_" + (pageIndex + 1).ToString(new string('0', digits), CultureInfo.InvariantCulture) + ".png";
            var path = System.IO.Path.Combine(outputDirectory, fileName);
            if (File.Exists(path))
            {
                throw new IOException("证据图片已存在，已阻止覆盖：" + path);
            }

            var start = pageIndex * linesPerPage;
            var count = Math.Min(linesPerPage, displayLines.Count - start);
            RenderPage(
                path,
                header,
                displayLines,
                start,
                count,
                pageIndex + 1,
                pageCount);
            rendered.Add(new RenderedEvidencePage(path, ComputeSha256(path)));
        }

        return new ReadOnlyCollection<RenderedEvidencePage>(rendered);
    }

    private void RenderPage(
        string targetPath,
        EvidenceHeader header,
        IReadOnlyList<string> lines,
        int lineStart,
        int lineCount,
        int pageNumber,
        int pageCount)
    {
        var visual = new DrawingVisual();
        using (var drawing = visual.RenderOpen())
        {
            drawing.DrawRectangle(Brushes.White, null, new Rect(0, 0, pageWidth, pageHeight));
            drawing.DrawRectangle(new SolidColorBrush(Color.FromRgb(20, 31, 48)), null, new Rect(0, 0, pageWidth, HeaderHeight));
            DrawHeader(drawing, header, pageNumber, pageCount);

            drawing.PushClip(new RectangleGeometry(new Rect(
                HorizontalMargin,
                HeaderHeight,
                pageWidth - (HorizontalMargin * 2),
                pageHeight - HeaderHeight - FooterHeight)));
            for (var index = 0; index < lineCount; index++)
            {
                drawing.DrawText(
                    Text(lines[lineStart + index], 14, Brushes.Black, "Consolas, Microsoft YaHei UI"),
                    new Point(HorizontalMargin, HeaderHeight + 4 + (index * BodyLineHeight)));
            }

            drawing.Pop();
            drawing.DrawLine(
                new Pen(new SolidColorBrush(Color.FromRgb(210, 215, 222)), 1),
                new Point(HorizontalMargin, pageHeight - FooterHeight),
                new Point(pageWidth - HorizontalMargin, pageHeight - FooterHeight));
        }

        var bitmap = new RenderTargetBitmap(pageWidth, pageHeight, Dpi, Dpi, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        bitmap.Freeze();
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        var temporaryPath = targetPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                8192,
                FileOptions.WriteThrough))
            {
                encoder.Save(stream);
                stream.Flush(true);
            }

            File.Move(temporaryPath, targetPath);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void DrawHeader(
        DrawingContext drawing,
        EvidenceHeader header,
        int pageNumber,
        int pageCount)
    {
        var primary = Brushes.White;
        var secondary = new SolidColorBrush(Color.FromRgb(196, 207, 224));
        drawing.DrawText(Text("等级保护测评证据", 24, primary, "Microsoft YaHei UI", FontWeights.SemiBold), new Point(HorizontalMargin, 18));
        drawing.DrawText(Text("项目：" + header.ProjectName, 15, primary, "Microsoft YaHei UI"), new Point(HorizontalMargin, 62));
        drawing.DrawText(Text("设备：" + header.DeviceName, 15, primary, "Microsoft YaHei UI"), new Point(HorizontalMargin, 92));
        drawing.DrawText(Text("测评项：" + header.CheckItem, 15, primary, "Microsoft YaHei UI"), new Point(HorizontalMargin, 122));
        drawing.DrawText(Text("命令：" + header.Command, 14, secondary, "Consolas, Microsoft YaHei UI"), new Point(HorizontalMargin, 154));
        drawing.DrawText(
            Text("执行时间：" + header.ExecutedAt.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture), 14, secondary, "Microsoft YaHei UI"),
            new Point(HorizontalMargin, 188));
        drawing.DrawText(
            Text("页码：" + pageNumber.ToString(CultureInfo.InvariantCulture) + "/" + pageCount.ToString(CultureInfo.InvariantCulture), 14, secondary, "Microsoft YaHei UI"),
            new Point(320, 188));
    }

    private static FormattedText Text(
        string value,
        double size,
        Brush brush,
        string fontFamily,
        FontWeight? weight = null)
    {
        return new FormattedText(
            value,
            CultureInfo.GetCultureInfo("zh-CN"),
            FlowDirection.LeftToRight,
            new Typeface(
                new FontFamily(fontFamily),
                FontStyles.Normal,
                weight ?? FontWeights.Normal,
                FontStretches.Normal),
            size,
            brush,
            pixelsPerDip: 1.0);
    }

    private IReadOnlyList<string> ProjectDisplayLines(string normalizedOutput)
    {
        var result = new List<string>();
        foreach (var logicalLine in normalizedOutput.Split(new[] { '\n' }, StringSplitOptions.None))
        {
            var expanded = ExpandTabs(logicalLine);
            if (expanded.Length == 0)
            {
                result.Add(string.Empty);
                continue;
            }

            AddMeasuredWrappedLines(expanded, result);
        }

        return result;
    }

    private void AddMeasuredWrappedLines(string line, ICollection<string> output)
    {
        var maximumWidth = pageWidth - (HorizontalMargin * 2);
        if (Text(line, 14, Brushes.Black, "Consolas, Microsoft YaHei UI")
            .WidthIncludingTrailingWhitespace <= maximumWidth)
        {
            output.Add(line);
            return;
        }

        var starts = StringInfo.ParseCombiningCharacters(line);
        var elementIndex = 0;
        while (elementIndex < starts.Length)
        {
            var low = 1;
            var high = starts.Length - elementIndex;
            var best = 0;
            while (low <= high)
            {
                var count = low + ((high - low) / 2);
                var candidate = SliceTextElements(line, starts, elementIndex, count);
                if (Text(candidate, 14, Brushes.Black, "Consolas, Microsoft YaHei UI")
                    .WidthIncludingTrailingWhitespace <= maximumWidth)
                {
                    best = count;
                    low = count + 1;
                }
                else
                {
                    high = count - 1;
                }
            }

            if (best == 0)
            {
                throw new ArgumentException("证据页面过窄，无法完整显示输出字符。", nameof(line));
            }

            output.Add(SliceTextElements(line, starts, elementIndex, best));
            elementIndex += best;
        }
    }

    private static string SliceTextElements(string value, int[] starts, int startElement, int elementCount)
    {
        var start = starts[startElement];
        var endElement = startElement + elementCount;
        var end = endElement < starts.Length ? starts[endElement] : value.Length;
        return value.Substring(start, end - start);
    }

    private static string ExpandTabs(string value)
    {
        var result = new System.Text.StringBuilder(value.Length);
        var column = 0;
        foreach (var character in value)
        {
            if (character == '\t')
            {
                var spaces = 4 - (column % 4);
                result.Append(' ', spaces);
                column += spaces;
            }
            else
            {
                result.Append(character);
                column += character > 255 ? 2 : 1;
            }
        }

        return result.ToString();
    }

    private void EnsureHeaderFits(EvidenceHeader header)
    {
        var maximumWidth = pageWidth - (HorizontalMargin * 2);
        var values = new[]
        {
            Text("项目：" + header.ProjectName, 15, Brushes.White, "Microsoft YaHei UI"),
            Text("设备：" + header.DeviceName, 15, Brushes.White, "Microsoft YaHei UI"),
            Text("测评项：" + header.CheckItem, 15, Brushes.White, "Microsoft YaHei UI"),
            Text("命令：" + header.Command, 14, Brushes.White, "Consolas, Microsoft YaHei UI")
        };
        if (values.Any(value => value.WidthIncludingTrailingWhitespace > maximumWidth))
        {
            throw new ArgumentException("证据页眉内容过长，无法完整显示，请缩短项目、设备、测评项名称或拆分命令。", nameof(header));
        }
    }

    private static string NormalizeLineEndings(string value)
    {
        return value.Replace("\r\n", "\n").Replace('\r', '\n');
    }

    private static string ComputeSha256(string path)
    {
        using (var stream = File.OpenRead(path))
        using (var sha256 = SHA256.Create())
        {
            return string.Concat(sha256.ComputeHash(stream).Select(value => value.ToString("x2", CultureInfo.InvariantCulture)));
        }
    }
}
