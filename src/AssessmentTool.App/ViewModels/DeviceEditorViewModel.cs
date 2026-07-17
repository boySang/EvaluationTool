using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App.ViewModels;

public enum DeviceEditorStep
{
    BasicInformation,
    ConnectionConfiguration,
    SaveAndTest
}

public sealed class DeviceEditorViewModel : INotifyPropertyChanged
{
    private string displayName = string.Empty;
    private string host = string.Empty;
    private string portText = "22";
    private string userName = string.Empty;
    private TargetCategory category = TargetCategory.Automatic;
    private DeviceEditorStep step = DeviceEditorStep.BasicInformation;
    private bool isOpen;
    private string validationMessage = "填写设备名称和地址后，继续配置连接。";

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

    public string UserName
    {
        get => userName;
        set
        {
            userName = value ?? string.Empty;
            Validate();
            OnPropertyChanged();
        }
    }

    public TargetCategory Category
    {
        get => category;
        set
        {
            if (category == value)
            {
                return;
            }

            category = value;
            Validate();
            OnPropertyChanged();
        }
    }

    public ConnectionProtocol Protocol => ConnectionProtocol.Ssh;

    public DeviceEditorStep Step
    {
        get => step;
        private set
        {
            if (step == value)
            {
                return;
            }

            step = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StepNumber));
            OnPropertyChanged(nameof(StepTitle));
            Validate();
        }
    }

    public bool IsOpen
    {
        get => isOpen;
        private set
        {
            if (isOpen == value)
            {
                return;
            }

            isOpen = value;
            OnPropertyChanged();
        }
    }

    public int StepNumber => (int)Step + 1;
    public string StepTitle => Step == DeviceEditorStep.BasicInformation
        ? "基本信息"
        : Step == DeviceEditorStep.ConnectionConfiguration
            ? "连接配置"
            : "保存与连接测试";

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
    public bool CanContinue => IsValid;

    public void Start()
    {
        DisplayName = string.Empty;
        Host = string.Empty;
        PortText = "22";
        UserName = string.Empty;
        Category = TargetCategory.Automatic;
        Step = DeviceEditorStep.BasicInformation;
        IsOpen = true;
        Validate();
    }

    public void Close()
    {
        IsOpen = false;
    }

    public void Next()
    {
        Validate();
        if (!CanContinue)
        {
            throw new InvalidOperationException(ValidationMessage);
        }

        if (Step == DeviceEditorStep.BasicInformation)
        {
            Step = DeviceEditorStep.ConnectionConfiguration;
        }
        else if (Step == DeviceEditorStep.ConnectionConfiguration)
        {
            Step = DeviceEditorStep.SaveAndTest;
        }
    }

    public void Back()
    {
        if (Step == DeviceEditorStep.SaveAndTest)
        {
            Step = DeviceEditorStep.ConnectionConfiguration;
        }
        else if (Step == DeviceEditorStep.ConnectionConfiguration)
        {
            Step = DeviceEditorStep.BasicInformation;
        }
    }

    private void Validate()
    {
        int port;
        var basicInformationValid = !string.IsNullOrWhiteSpace(DisplayName)
            && !string.IsNullOrWhiteSpace(Host);
        var connectionValid = basicInformationValid
            && !string.IsNullOrWhiteSpace(UserName)
            && int.TryParse(PortText, out port)
            && port >= 1
            && port <= 65535;
        IsValid = Step == DeviceEditorStep.BasicInformation
            ? basicInformationValid
            : connectionValid;
        ValidationMessage = IsValid
            ? Step == DeviceEditorStep.SaveAndTest
                ? "设备资料已就绪；保存后先探测主机指纹，不会直接使用密码登录。"
                : "本步骤信息完整，可以继续。"
            : Step == DeviceEditorStep.BasicInformation
                ? "请填写设备名称和主机地址。"
                : "请填写 SSH 用户名和 1–65535 范围内的端口。";
        OnPropertyChanged(nameof(IsValid));
        OnPropertyChanged(nameof(CanContinue));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
