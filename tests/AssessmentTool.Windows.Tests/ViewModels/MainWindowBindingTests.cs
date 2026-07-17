using System;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class MainWindowBindingTests
{
    [Fact]
    public void Display_only_controls_use_one_way_bindings()
    {
        var document = XDocument.Load(FindMainWindowXaml());
        var violations = document
            .Descendants()
            .Where(element =>
                element.Name.LocalName == "ProgressBar"
                || (element.Name.LocalName == "TextBox"
                    && string.Equals((string?)element.Attribute("IsReadOnly"), "True", StringComparison.OrdinalIgnoreCase)))
            .SelectMany(element => element.Attributes()
                .Where(attribute => attribute.Value.StartsWith("{Binding ", StringComparison.Ordinal)
                    && !attribute.Value.Contains("Mode=OneWay"))
                .Select(attribute => element.Name.LocalName + "." + attribute.Name.LocalName))
            .ToArray();

        Assert.Empty(violations);
    }

    [Fact]
    public void Main_shell_exposes_compact_navigation_and_read_only_dashboard()
    {
        var document = XDocument.Load(FindMainWindowXaml());
        var window = document.Root ?? throw new InvalidOperationException("Main window root is missing.");
        var names = window.DescendantsAndSelf()
            .SelectMany(element => element.Attributes()
                .Where(attribute => attribute.Name.LocalName == "Name")
                .Select(attribute => attribute.Value))
            .ToArray();
        var text = string.Join(" ", window.DescendantsAndSelf()
            .SelectMany(element => element.Attributes())
            .Where(attribute => attribute.Name.LocalName == "Text" || attribute.Name.LocalName == "Content")
            .Select(attribute => attribute.Value));

        Assert.Equal("1440", (string?)window.Attribute("Width"));
        Assert.Equal("900", (string?)window.Attribute("Height"));
        Assert.Contains("ShellNavigation", names);
        Assert.Contains("ReadOnlyStatusBadge", names);
        Assert.Contains("DashboardDeviceCount", names);
        Assert.Contains("DeviceListPanel", names);
        Assert.Contains("DeviceWizardPanel", names);
        Assert.Contains("命令库", text);
        Assert.Contains("组件中心", text);
        Assert.Contains("自动识别（推荐）", text);
        Assert.Contains("SSH 用户名 *", text);
        Assert.Contains("自动探测指纹 → 人工确认 → 无命令测试登录", text);
        Assert.Contains("确认并测试登录", text);
        Assert.DoesNotContain("扫描内网", text);
        Assert.DoesNotContain("漏洞扫描", text);
    }

    [Fact]
    public void Every_tab_item_has_at_most_one_content_child()
    {
        var document = XDocument.Load(FindMainWindowXaml());
        var violations = document
            .Descendants()
            .Where(element => element.Name.LocalName == "TabItem")
            .Where(element => element.Elements()
                .Count(child => child.Name.LocalName != "TabItem.Header") > 1)
            .ToArray();

        Assert.Empty(violations);
    }

    [Fact]
    public void Collection_page_exposes_detection_confirmation_and_completed_command_bindings()
    {
        var source = File.ReadAllText(FindMainWindowXaml());

        Assert.Contains("Collection.DetectionCandidates", source);
        Assert.Contains("Collection.ConfirmDetectionCommand", source);
        Assert.Contains("CommandParameter=\"{Binding}\"", source);
        Assert.Contains("Collection.CompletedCommands", source);
        Assert.Contains("EvidenceCenter.Items", source);
        Assert.Contains("EvidenceCenter.RefreshCommand", source);
        Assert.Contains("EvidenceCenter.VerifyCommand", source);
        Assert.Contains("EvidenceCenter.OpenFolderCommand", source);
        Assert.Contains("ShaStatusText", source);
        Assert.Contains("RawOutputPathText", source);
        Assert.Contains("复核文件 SHA-256", source);
        Assert.Contains("开始只读采集", source);
        Assert.DoesNotContain("开始只读采集（尚未接通）", source);
    }

    [Fact]
    public void Evidence_center_primary_action_style_is_declared()
    {
        var mainWindow = File.ReadAllText(FindMainWindowXaml());
        var themePath = Path.Combine(
            Path.GetDirectoryName(FindMainWindowXaml())!,
            "Themes",
            "Fluent.xaml");
        var theme = File.ReadAllText(themePath);

        Assert.Contains("FluentPrimaryButtonStyle", mainWindow);
        Assert.Contains("x:Key=\"FluentPrimaryButtonStyle\"", theme);
    }

    private static string FindMainWindowXaml()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "src", "AssessmentTool.App", "MainWindow.xaml");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("MainWindow.xaml could not be located from the test output directory.");
    }
}
