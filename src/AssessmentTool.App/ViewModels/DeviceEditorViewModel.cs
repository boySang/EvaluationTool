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
    private SshAuthenticationMethod authenticationMethod = SshAuthenticationMethod.Password;
    private bool hasPassword;
    private char[]? privateKeyMaterial;
    private string privateKeyFileName = string.Empty;
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

    public SshAuthenticationMethod AuthenticationMethod
    {
        get => authenticationMethod;
        set
        {
            if (!Enum.IsDefined(typeof(SshAuthenticationMethod), value))
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, "SSH 身份验证方式无效。");
            }

            if (authenticationMethod == value)
            {
                return;
            }

            ClearPrivateKeyMaterial();
            hasPassword = false;
            authenticationMethod = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsPasswordAuthentication));
            OnPropertyChanged(nameof(IsPrivateKeyAuthentication));
            Validate();
        }
    }

    public bool IsPasswordAuthentication => AuthenticationMethod == SshAuthenticationMethod.Password;
    public bool IsPrivateKeyAuthentication => AuthenticationMethod == SshAuthenticationMethod.PrivateKey;
    public bool HasPrivateKeyMaterial => privateKeyMaterial != null && privateKeyMaterial.Length > 0;
    public string PrivateKeyFileName => privateKeyFileName;

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
        ClearSensitiveMaterial();
        DisplayName = string.Empty;
        Host = string.Empty;
        PortText = "22";
        UserName = string.Empty;
        Category = TargetCategory.Automatic;
        AuthenticationMethod = SshAuthenticationMethod.Password;
        Step = DeviceEditorStep.BasicInformation;
        IsOpen = true;
        Validate();
    }

    public void Close()
    {
        ClearSensitiveMaterial();
        IsOpen = false;
    }

    public void SetPasswordAvailability(bool value)
    {
        if (hasPassword == value)
        {
            return;
        }

        hasPassword = value;
        Validate();
    }

    public void SetPrivateKeyMaterial(char[] material, string safeFileName)
    {
        if (material == null)
        {
            throw new ArgumentNullException(nameof(material));
        }

        if (material.Length == 0)
        {
            throw new ArgumentException("PuTTY PPK 私钥内容为空。", nameof(material));
        }

        if (string.IsNullOrWhiteSpace(safeFileName))
        {
            throw new ArgumentException("PuTTY PPK 私钥文件名不能为空。", nameof(safeFileName));
        }

        ClearPrivateKeyMaterial();
        privateKeyMaterial = material;
        privateKeyFileName = safeFileName;
        OnPropertyChanged(nameof(HasPrivateKeyMaterial));
        OnPropertyChanged(nameof(PrivateKeyFileName));
        Validate();
    }

    public char[] TakePrivateKeyMaterial()
    {
        if (!HasPrivateKeyMaterial)
        {
            throw new InvalidOperationException("请先选择有效的 PuTTY PPK 私钥文件。");
        }

        var material = privateKeyMaterial!;
        privateKeyMaterial = null;
        privateKeyFileName = string.Empty;
        OnPropertyChanged(nameof(HasPrivateKeyMaterial));
        OnPropertyChanged(nameof(PrivateKeyFileName));
        Validate();
        return material;
    }

    public void ClearSensitiveMaterial()
    {
        hasPassword = false;
        ClearPrivateKeyMaterial();
        Validate();
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
            && port <= 65535
            && (AuthenticationMethod == SshAuthenticationMethod.Password
                ? hasPassword
                : HasPrivateKeyMaterial);
        IsValid = Step == DeviceEditorStep.BasicInformation
            ? basicInformationValid
            : connectionValid;
        ValidationMessage = IsValid
            ? Step == DeviceEditorStep.SaveAndTest
                ? "设备资料已就绪；保存后先探测主机指纹，再由人工确认并进行无命令登录测试。"
                : "本步骤信息完整，可以继续。"
            : Step == DeviceEditorStep.BasicInformation
                ? "请填写设备名称和主机地址。"
                : AuthenticationMethod == SshAuthenticationMethod.Password && !hasPassword
                    ? "请填写 SSH 登录密码。"
                    : AuthenticationMethod == SshAuthenticationMethod.PrivateKey && !HasPrivateKeyMaterial
                        ? "请选择未加密的 PuTTY PPK v2 或 v3 私钥。"
                        : "请填写 SSH 用户名和 1–65535 范围内的端口。";
        OnPropertyChanged(nameof(IsValid));
        OnPropertyChanged(nameof(CanContinue));
    }

    private void ClearPrivateKeyMaterial()
    {
        if (privateKeyMaterial != null)
        {
            Array.Clear(privateKeyMaterial, 0, privateKeyMaterial.Length);
            privateKeyMaterial = null;
        }

        if (privateKeyFileName.Length > 0)
        {
            privateKeyFileName = string.Empty;
            OnPropertyChanged(nameof(PrivateKeyFileName));
        }

        OnPropertyChanged(nameof(HasPrivateKeyMaterial));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
