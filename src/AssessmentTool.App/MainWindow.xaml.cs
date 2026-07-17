using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using System.Windows.Controls;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
    }

    private MainViewModel ViewModel => (MainViewModel)DataContext;

    private void NavigateToDevices_Click(object sender, RoutedEventArgs eventArgs)
    {
        ShellNavigation.SelectedIndex = 2;
    }

    private void NavigateToCollection_Click(object sender, RoutedEventArgs eventArgs)
    {
        ShellNavigation.SelectedIndex = 3;
    }

    private void NavigateToComponents_Click(object sender, RoutedEventArgs eventArgs)
    {
        ShellNavigation.SelectedIndex = 6;
    }

    private void OpenDeviceWizard_Click(object sender, RoutedEventArgs eventArgs)
    {
        DevicePasswordBox.Clear();
        ViewModel.DeviceEditor.Start();
    }

    private void CancelDeviceWizard_Click(object sender, RoutedEventArgs eventArgs)
    {
        DevicePasswordBox.Clear();
        ViewModel.DeviceEditor.Close();
    }

    private void DeviceWizardNext_Click(object sender, RoutedEventArgs eventArgs)
    {
        if (ViewModel.DeviceEditor.Step == DeviceEditorStep.ConnectionConfiguration
            && DevicePasswordBox.SecurePassword.Length == 0)
        {
            MessageBox.Show(
                "请输入登录密码后继续。密码只会在保存时进入安全缓冲区。",
                "连接资料未完成",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        ViewModel.DeviceEditor.Next();
    }

    private void DeviceWizardBack_Click(object sender, RoutedEventArgs eventArgs)
    {
        ViewModel.DeviceEditor.Back();
    }

    private async void CreateProject_Click(object sender, RoutedEventArgs eventArgs)
    {
        if (ViewModel.Workspace != null)
        {
            await ViewModel.Workspace.CreateProjectAsync();
        }
    }

    private async void ProjectSelection_Changed(object sender, SelectionChangedEventArgs eventArgs)
    {
        if (ViewModel.Workspace != null && ((ListBox)sender).SelectedItem is ProjectRecord project)
        {
            await ViewModel.Workspace.SelectProjectAsync(project);
        }
    }

    private async void DeviceSelection_Changed(object sender, SelectionChangedEventArgs eventArgs)
    {
        await ViewModel.DeviceConnection.SelectDeviceAsync(
            ((ListBox)sender).SelectedItem as DeviceRecord);
    }

    private async void ProbeHostKey_Click(object sender, RoutedEventArgs eventArgs)
    {
        await ViewModel.DeviceConnection.ProbeAsync();
    }

    private async void ConfirmHostKeyAndTest_Click(object sender, RoutedEventArgs eventArgs)
    {
        var result = MessageBox.Show(
            "请先通过客户提供的信息、设备控制台或管理员核对完整 SSH 主机指纹。\n\n确认当前显示的指纹一致，并继续进行不发送命令的登录测试吗？",
            "人工确认 SSH 主机指纹",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (result == MessageBoxResult.Yes)
        {
            await ViewModel.DeviceConnection.ConfirmAndTestAsync();
        }
    }

    private async void SaveDevice_Click(object sender, RoutedEventArgs eventArgs)
    {
        if (ViewModel.Workspace == null)
        {
            return;
        }

        if (DevicePasswordBox.SecurePassword.Length == 0)
        {
            MessageBox.Show(
                "登录密码为空，设备尚未保存。请返回连接配置并填写密码。",
                "连接资料未完成",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        ViewModel.Workspace.DeviceDisplayName = ViewModel.DeviceEditor.DisplayName;
        ViewModel.Workspace.DeviceHost = ViewModel.DeviceEditor.Host;
        ViewModel.Workspace.DevicePortText = ViewModel.DeviceEditor.PortText;
        ViewModel.Workspace.DeviceUserName = ViewModel.DeviceEditor.UserName;
        ViewModel.Workspace.DeviceCategory = ViewModel.DeviceEditor.Category;
        var password = CopyPassword(DevicePasswordBox.SecurePassword);
        try
        {
            await ViewModel.Workspace.AddDeviceAsync(password);
            if (ViewModel.Workspace.State == ProjectWorkspaceState.Ready)
            {
                ViewModel.DeviceEditor.Close();
            }
        }
        finally
        {
            Array.Clear(password, 0, password.Length);
            DevicePasswordBox.Clear();
        }
    }

    private static char[] CopyPassword(SecureString securePassword)
    {
        if (securePassword == null || securePassword.Length == 0)
        {
            return Array.Empty<char>();
        }

        var pointer = IntPtr.Zero;
        try
        {
            pointer = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
            var password = new char[securePassword.Length];
            Marshal.Copy(pointer, password, 0, password.Length);
            return password;
        }
        finally
        {
            if (pointer != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(pointer);
            }
        }
    }
}
