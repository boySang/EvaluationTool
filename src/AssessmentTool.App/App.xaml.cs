using System;
using System.Linq;
using System.Windows;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App;

public partial class App : Application
{
    private const string LightTheme = "Themes/Colors.xaml";
    private const string DarkTheme = "Themes/Colors.Dark.xaml";

    protected override async void OnStartup(StartupEventArgs eventArgs)
    {
        base.OnStartup(eventArgs);
        try
        {
            var paths = ApplicationStoragePaths.ForCurrentUser();
            var repository = new SqliteProjectRepository(paths.SqliteConnectionString);
            var credentialVault = new DpapiCredentialVault(paths.CredentialRootDirectory);
            var workspace = new ProjectWorkspaceViewModel(
                new ProjectWorkspaceService(repository, credentialVault));
            await workspace.InitializeAsync();
            if (workspace.State == ProjectWorkspaceState.Failed)
            {
                MessageBox.Show(
                    workspace.WhatHappened + Environment.NewLine + Environment.NewLine
                    + workspace.HowToFix + Environment.NewLine + Environment.NewLine
                    + "技术信息：" + workspace.TechnicalDetails,
                    "软件初始化失败",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                Shutdown(1);
                return;
            }

            var componentCenter = new ComponentCenterViewModel(new ComponentStatusService());
            await componentCenter.RefreshAsync();
            var mainViewModel = new MainViewModel(
                workspace,
                new CollectionViewModel(new UnavailableCollectionWorkflowService()),
                componentCenter,
                ToggleTheme);
            var window = new MainWindow(mainViewModel);
            MainWindow = window;
            window.Show();
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                "软件无法初始化本机项目数据。请确认软件包完整，并检查当前 Windows 用户的本地数据目录权限。"
                + Environment.NewLine + Environment.NewLine
                + "技术信息：" + exception.GetType().Name,
                "软件初始化失败",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
        }
    }

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
