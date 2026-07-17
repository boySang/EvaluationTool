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
                || element.Name.LocalName == "Run"
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
    public void Only_device_management_list_can_write_the_selected_device()
    {
        var document = XDocument.Load(FindMainWindowXaml());
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        var writableSelections = document
            .Descendants(presentation + "ListBox")
            .Select(element => (string?)element.Attribute("SelectedItem"))
            .Where(value => value != null
                && value.IndexOf("Workspace.SelectedDevice", StringComparison.Ordinal) >= 0
                && value.IndexOf("Mode=TwoWay", StringComparison.Ordinal) >= 0)
            .ToArray();

        Assert.Single(writableSelections);
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
        Assert.Contains("密码验证", text);
        Assert.Contains("PuTTY PPK 私钥", text);
        Assert.Contains("自动探测指纹 → 人工确认 → 无命令测试登录", text);
        Assert.Contains("确认并测试登录", text);
        Assert.Contains("设备身份", text);
        Assert.Contains("任务历史", text);
        Assert.Contains("恢复待入库证据", text);
        Assert.Contains("保留识别依据、可信度和人工确认来源", text);
        Assert.DoesNotContain("扫描内网", text);
        Assert.DoesNotContain("漏洞扫描", text);
        Assert.Contains("TaskHistory.Items", File.ReadAllText(FindMainWindowXaml()));
    }

    [Fact]
    public void Device_page_binds_latest_persisted_identification_and_refreshes_on_selection()
    {
        var mainWindowPath = FindMainWindowXaml();
        var xaml = File.ReadAllText(mainWindowPath);
        var mainViewModel = File.ReadAllText(Path.Combine(
            Path.GetDirectoryName(mainWindowPath)!,
            "ViewModels",
            "MainViewModel.cs"));

        Assert.Contains("Workspace.SelectedIdentification.Category", xaml);
        Assert.Contains("Workspace.SelectedIdentification.Evidence", xaml);
        Assert.Contains("Workspace.IdentificationStatusMessage", xaml);
        Assert.Contains("RefreshSelectedIdentificationAsync", mainViewModel);
    }

    [Fact]
    public void Device_editor_exposes_private_key_picker_without_binding_a_local_path()
    {
        var xaml = File.ReadAllText(FindMainWindowXaml());
        var codeBehind = File.ReadAllText(Path.ChangeExtension(FindMainWindowXaml(), ".xaml.cs"));

        Assert.Contains("DeviceEditor.AuthenticationMethod", xaml);
        Assert.Contains("DeviceEditor.PrivateKeyFileName", xaml);
        Assert.Contains("SelectPrivateKey_Click", xaml);
        Assert.Contains("不保存原始路径", xaml);
        Assert.Contains("PpkPrivateKeyMaterial.MaximumEncodedBytes", codeBehind);
        Assert.Contains("StrictUtf8.GetChars", codeBehind);
        Assert.Contains("GetSafeFileName(dialog.FileName)", codeBehind);
        Assert.DoesNotContain("PrivateKeyPath", xaml);
        Assert.DoesNotContain("privateKeyPath", codeBehind);
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
        Assert.Contains("EvidenceCenter.DatabaseConfirmations", source);
        Assert.Contains("EvidenceCenter.HasDatabaseConfirmations", source);
        Assert.Contains("数据库人工确认审计", source);
        Assert.Contains("不表示已经连接数据库或执行 SQL", source);
        Assert.Contains("ShaStatusText", source);
        Assert.Contains("RawOutputPathText", source);
        Assert.Contains("复核文件 SHA-256", source);
        Assert.Contains("开始只读采集", source);
        Assert.DoesNotContain("开始只读采集（尚未接通）", source);
    }

    [Fact]
    public void Collection_page_exposes_database_candidate_confirmation_without_database_connection_actions()
    {
        var source = File.ReadAllText(FindMainWindowXaml());

        Assert.Contains("Value=\"AwaitingDatabaseConfirmation\"", source);
        Assert.Contains("Value=\"ConfirmingDatabase\"", source);
        Assert.Contains("Collection.DatabaseCandidates", source);
        Assert.Contains("Collection.ConfirmDatabaseCommand", source);
        Assert.Contains("Collection.SelectedDatabaseCandidate.Product", source);
        Assert.Contains("Collection.SelectedDatabaseCandidate.InstanceName", source);
        Assert.Contains("Collection.SelectedDatabaseCandidate.InstallationType", source);
        Assert.Contains("Value=\"DatabaseConfirmed\"", source);
        Assert.Contains("Content=\"确认此数据库实例\"", source);
        Assert.Contains("CommandParameter=\"{Binding}\"", source);
        Assert.Contains("此操作仅确认主机侧只读发现结果，本阶段不执行 SQL，也不建立数据库直连。", source);
        Assert.Contains("仅确认发现结果，本阶段未执行 SQL，也未建立数据库直连。", source);
        Assert.Contains("Binding=\"{Binding Collection.Error}\" Value=\"{x:Null}\"", source);
        Assert.DoesNotContain("Content=\"连接数据库\"", source);
        Assert.DoesNotContain("Content=\"执行 SQL\"", source);
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

    [Fact]
    public void Command_library_separates_drafts_publication_and_project_version_locks()
    {
        var document = XDocument.Load(FindMainWindowXaml());
        var commandLibrary = Assert.Single(document.Descendants(), element =>
            element.Name.LocalName == "TabItem"
            && string.Equals((string?)element.Attribute("Header"), "命令库", StringComparison.Ordinal));
        var source = commandLibrary.ToString();

        Assert.Contains("CommandLibrary.ImportCommand", source);
        Assert.Contains("CommandLibrary.RefreshCommand", source);
        Assert.Contains("CommandLibrary.PublishCommand", source);
        Assert.Contains("CommandLibrary.LockCommand", source);
        Assert.Contains("CommandLibrary.ReviewerName", source);
        Assert.Contains("待校验", source);
        Assert.Contains("草稿不能直接执行", source);
        Assert.Contains("不可变版本", source);
        Assert.Contains("不覆盖历史", source);
        Assert.Contains("不会连接客户设备", source);
        Assert.Contains("单个 JSON 文件最大 1 MB", source);
        Assert.DoesNotContain("Content=\"执行", source);
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
