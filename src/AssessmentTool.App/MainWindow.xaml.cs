using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Credentials;
using Microsoft.Win32;

namespace AssessmentTool.App;

public partial class MainWindow : Window
{
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

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
            && !ViewModel.DeviceEditor.CanContinue)
        {
            MessageBox.Show(
                ViewModel.DeviceEditor.ValidationMessage,
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

    private void DevicePassword_Changed(object sender, RoutedEventArgs eventArgs)
    {
        ViewModel.DeviceEditor.SetPasswordAvailability(DevicePasswordBox.SecurePassword.Length > 0);
    }

    private void DeviceAuthentication_Changed(object sender, SelectionChangedEventArgs eventArgs)
    {
        if (!IsInitialized || DevicePasswordBox == null)
        {
            return;
        }

        DevicePasswordBox.Clear();
        ViewModel.DeviceEditor.SetPasswordAvailability(false);
    }

    private void SelectPrivateKey_Click(object sender, RoutedEventArgs eventArgs)
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择 PuTTY PPK 私钥",
            Filter = "PuTTY 私钥 (*.ppk)|*.ppk|所有文件 (*.*)|*.*",
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        byte[]? encoded = null;
        char[]? material = null;
        try
        {
            var file = new FileInfo(dialog.FileName);
            if (file.Length <= 0 || file.Length > PpkPrivateKeyMaterial.MaximumEncodedBytes)
            {
                throw new InvalidDataException("私钥文件必须大于 0 字节且不超过 256 KB。");
            }

            encoded = ReadBoundedPrivateKey(dialog.FileName);

            material = StrictUtf8.GetChars(encoded);
            PpkPrivateKeyMaterial.Validate(material);
            ViewModel.DeviceEditor.SetPrivateKeyMaterial(material, GetSafeFileName(dialog.FileName));
            material = null;
        }
        catch (Exception exception) when (exception is IOException
            || exception is UnauthorizedAccessException
            || exception is InvalidDataException
            || exception is DecoderFallbackException
            || exception is PpkPrivateKeyException)
        {
            MessageBox.Show(
                "无法使用所选私钥。\n\n发生了什么：文件无法读取或不是受支持的未加密 PuTTY PPK v2/v3。\n怎么处理：请确认文件不超过 256 KB、采用 UTF-8 编码且 Encryption 为 none。\n\n技术信息：" + exception.GetType().Name,
                "私钥不可用",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            if (material != null)
            {
                Array.Clear(material, 0, material.Length);
            }

            if (encoded != null)
            {
                Array.Clear(encoded, 0, encoded.Length);
            }
        }
    }

    private static byte[] ReadBoundedPrivateKey(string path)
    {
        using (var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            4096,
            FileOptions.SequentialScan))
        using (var memory = new MemoryStream())
        {
            var buffer = new byte[4096];
            try
            {
                while (true)
                {
                    var read = stream.Read(buffer, 0, buffer.Length);
                    if (read == 0)
                    {
                        break;
                    }

                    if (memory.Length + read > PpkPrivateKeyMaterial.MaximumEncodedBytes)
                    {
                        throw new InvalidDataException("私钥文件不能超过 256 KB。");
                    }

                    memory.Write(buffer, 0, read);
                }

                if (memory.Length == 0)
                {
                    throw new InvalidDataException("私钥文件不能为空。");
                }

                return memory.ToArray();
            }
            finally
            {
                Array.Clear(buffer, 0, buffer.Length);
                var internalBuffer = memory.GetBuffer();
                Array.Clear(internalBuffer, 0, internalBuffer.Length);
            }
        }
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

        if (!ViewModel.DeviceEditor.CanContinue)
        {
            MessageBox.Show(
                ViewModel.DeviceEditor.ValidationMessage,
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
        char[] secretMaterial;
        if (ViewModel.DeviceEditor.AuthenticationMethod == SshAuthenticationMethod.PrivateKey)
        {
            secretMaterial = ViewModel.DeviceEditor.TakePrivateKeyMaterial();
        }
        else
        {
            secretMaterial = CopyPassword(DevicePasswordBox.SecurePassword);
        }

        try
        {
            if (ViewModel.DeviceEditor.AuthenticationMethod == SshAuthenticationMethod.PrivateKey)
            {
                await ViewModel.Workspace.AddPrivateKeyDeviceAsync(secretMaterial);
            }
            else
            {
                await ViewModel.Workspace.AddDeviceAsync(secretMaterial);
            }

            if (ViewModel.Workspace.State == ProjectWorkspaceState.Ready)
            {
                ViewModel.DeviceEditor.Close();
            }
        }
        finally
        {
            Array.Clear(secretMaterial, 0, secretMaterial.Length);
            DevicePasswordBox.Clear();
            ViewModel.DeviceEditor.ClearSensitiveMaterial();
        }
    }

    private static string GetSafeFileName(string path)
    {
        var fileName = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return "已选择私钥.ppk";
        }

        var characters = fileName.ToCharArray();
        try
        {
            for (var index = 0; index < characters.Length; index++)
            {
                if (char.IsControl(characters[index]))
                {
                    characters[index] = '_';
                }
            }

            var safeName = new string(characters);
            return safeName.Length <= 120 ? safeName : safeName.Substring(0, 120);
        }
        finally
        {
            Array.Clear(characters, 0, characters.Length);
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
