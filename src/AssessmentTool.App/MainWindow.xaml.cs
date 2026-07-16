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

    private async void SaveDevice_Click(object sender, RoutedEventArgs eventArgs)
    {
        if (ViewModel.Workspace == null)
        {
            return;
        }

        var password = CopyPassword(DevicePasswordBox.SecurePassword);
        try
        {
            await ViewModel.Workspace.AddDeviceAsync(password);
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
