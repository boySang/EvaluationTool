using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using AssessmentTool.App.Services;
using AssessmentTool.App.Startup;
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
        var startupSuccessMarker = new StartupSuccessMarker();
        startupSuccessMarker.BeginStartup();
        var startupStage = "确定本地数据目录";
        try
        {
            base.OnStartup(eventArgs);
            var paths = ApplicationStoragePaths.ForCurrentUser();
            startupStage = "创建本地项目数据库";
            var repository = new SqliteProjectRepository(paths.SqliteConnectionString);
            startupStage = "初始化安全凭据存储";
            var credentialVault = new DpapiCredentialVault(paths.CredentialRootDirectory);
            startupStage = "打开本地项目数据库";
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

            startupStage = "恢复异常中断的采集任务";
            await repository.MarkInterruptedCollectionTasksAsync(DateTimeOffset.UtcNow);

            startupStage = "检查 SSH 连接组件";
            var componentCenter = new ComponentCenterViewModel(new ComponentStatusService());
            await componentCenter.RefreshAsync();
            startupStage = "加载本地命令草稿";
            var commandPackReleaseService = new CommandPackReleaseService(repository, repository);
            var commandLibrary = new CommandLibraryViewModel(
                new CommandDraftService(repository),
                new JsonCommandDraftFilePicker(),
                commandPackReleaseService);
            await commandLibrary.InitializeAsync();
            await commandLibrary.SelectProjectAsync(workspace.SelectedProject);
            startupStage = "加载软件主界面";
            var mainViewModel = new MainViewModel(
                workspace,
                new CollectionViewModel(
                    new CollectionWorkflowService(
                        credentialVault,
                        new CollectionEvidenceService(repository),
                        repository,
                        commandPackReleaseService),
                    new DatabaseConfirmationService(repository),
                    repository,
                    new HostSoftwareCandidateConfirmationService(repository),
                    repository),
                componentCenter,
                new DeviceConnectionViewModel(
                    new SshConnectionWorkflowService(repository, credentialVault)),
                ToggleTheme,
                new EvidenceCenterViewModel(
                    new EvidenceCenterService(repository, repository),
                    new ProjectEvidenceFolderLauncher(repository),
                    new EvidenceRecoveryService(repository),
                    new ProjectEvidenceFileLocator(repository),
                    new ProjectEvidenceManifestExporter(repository),
                    new JsonEvidenceManifestExportFilePicker(),
                    new ProjectEvidencePackageExporter(repository),
                    new ZipEvidencePackageExportFilePicker()),
                commandLibrary,
                new CollectionTaskHistoryViewModel(repository));
            var window = new MainWindow(mainViewModel);
            MainWindow = window;
            EventHandler? contentRenderedHandler = null;
            contentRenderedHandler = (sender, args) =>
            {
                window.ContentRendered -= contentRenderedHandler;
                startupSuccessMarker.TryMarkMainWindowDisplayed();
            };
            window.ContentRendered += contentRenderedHandler;
            window.Show();
        }
        catch (Exception exception)
        {
            var diagnosticPath = TryWriteStartupDiagnostic(startupStage, exception);
            MessageBox.Show(
                "软件启动失败，未对客户设备执行任何操作。"
                + Environment.NewLine + Environment.NewLine
                + "失败阶段：" + startupStage
                + Environment.NewLine
                + "具体原因：" + exception.Message
                + Environment.NewLine
                + "技术类型：" + exception.GetType().Name
                + Environment.NewLine
                + "诊断日志：" + diagnosticPath,
                "软件初始化失败",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    private static string TryWriteStartupDiagnostic(string startupStage, Exception exception)
    {
        var path = Path.Combine(Path.GetTempPath(), "EvaluationTool-startup.log");
        try
        {
            using (var writer = new StreamWriter(path, true, new UTF8Encoding(false)))
            {
                writer.WriteLine("[{0:O}] Startup failed during: {1}", DateTimeOffset.Now, startupStage);
                writer.WriteLine(exception);
                writer.WriteLine();
            }

            return path;
        }
        catch
        {
            return "无法写入临时诊断日志";
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
