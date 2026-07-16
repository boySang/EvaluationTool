using System;
using System.Linq;
using System.Windows;

namespace AssessmentTool.App;

public partial class App : Application
{
    private const string LightTheme = "Themes/Colors.xaml";
    private const string DarkTheme = "Themes/Colors.Dark.xaml";

    public static void ToggleTheme()
    {
        var resources = Current?.Resources.MergedDictionaries;
        if (resources == null)
        {
            return;
        }

        var colors = resources.FirstOrDefault(dictionary =>
            dictionary.Source != null
            && (dictionary.Source.OriginalString.EndsWith(LightTheme, StringComparison.OrdinalIgnoreCase)
                || dictionary.Source.OriginalString.EndsWith(DarkTheme, StringComparison.OrdinalIgnoreCase)));
        if (colors == null)
        {
            return;
        }

        var isDark = colors.Source.OriginalString.EndsWith(DarkTheme, StringComparison.OrdinalIgnoreCase);
        colors.Source = new Uri(isDark ? LightTheme : DarkTheme, UriKind.Relative);
    }
}
