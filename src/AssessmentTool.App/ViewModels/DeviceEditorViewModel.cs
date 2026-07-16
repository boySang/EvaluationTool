using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace AssessmentTool.App.ViewModels;

public sealed class DeviceEditorViewModel : INotifyPropertyChanged
{
    private string displayName = string.Empty;
    private string host = string.Empty;
    private string portText = "22";
    private string validationMessage = "填写设备名称和地址后，可继续配置 SSH 认证与主机指纹。";

    public event PropertyChangedEventHandler? PropertyChanged;

    public string DisplayName
    {
        get => displayName;
        set
        {
            displayName = value ?? string.Empty;
            Validate();
            OnPropertyChanged();
        }
    }

    public string Host
    {
        get => host;
        set
        {
            host = value ?? string.Empty;
            Validate();
            OnPropertyChanged();
        }
    }

    public string PortText
    {
        get => portText;
        set
        {
            portText = value ?? string.Empty;
            Validate();
            OnPropertyChanged();
        }
    }

    public string ValidationMessage
    {
        get => validationMessage;
        private set
        {
            validationMessage = value;
            OnPropertyChanged();
        }
    }

    public bool IsValid { get; private set; }

    private void Validate()
    {
        int port;
        IsValid = !string.IsNullOrWhiteSpace(DisplayName)
            && !string.IsNullOrWhiteSpace(Host)
            && int.TryParse(PortText, out port)
            && port >= 1
            && port <= 65535;
        ValidationMessage = IsValid
            ? "基础连接信息有效；保存前仍需确认凭据和 SSH 主机指纹。"
            : "请填写设备名称、地址和 1–65535 范围内的端口。";
        OnPropertyChanged(nameof(IsValid));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
