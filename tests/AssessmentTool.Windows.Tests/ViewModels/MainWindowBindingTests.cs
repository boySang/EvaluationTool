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
