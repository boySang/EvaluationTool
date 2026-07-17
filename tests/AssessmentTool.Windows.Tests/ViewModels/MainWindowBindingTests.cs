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
        var names = document.DescendantsAndSelf()
            .SelectMany(element => element.Attributes()
                .Where(attribute => attribute.Name.LocalName == "Name")
                .Select(attribute => attribute.Value))
            .ToArray();
        var text = string.Join(" ", document.DescendantsAndSelf()
            .SelectMany(element => element.Attributes())
            .Where(attribute => attribute.Name.LocalName == "Text" || attribute.Name.LocalName == "Content")
            .Select(attribute => attribute.Value));

        Assert.Equal("1440", (string?)window.Attribute("Width"));
        Assert.Equal("900", (string?)window.Attribute("Height"));
        Assert.Contains("ShellNavigation", names);
        Assert.Contains("ReadOnlyStatusBadge", names);
        Assert.Contains("DashboardDeviceCount", names);
        Assert.Contains("命令库", text);
        Assert.Contains("组件中心", text);
        Assert.DoesNotContain("扫描内网", text);
        Assert.DoesNotContain("漏洞扫描", text);
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
