using System;
using System.Globalization;
using System.Windows.Data;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App.Converters;

public sealed class DeviceMetadataConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is TargetCategory category)
        {
            switch (category)
            {
                case TargetCategory.Automatic:
                    return "自动识别";
                case TargetCategory.NetworkDevice:
                    return "网络设备";
                case TargetCategory.Server:
                    return "服务器";
                case TargetCategory.Database:
                    return "数据库";
                case TargetCategory.Middleware:
                    return "中间件";
                case TargetCategory.SecurityDevice:
                    return "安全设备";
            }
        }

        if (value is ConnectionProtocol protocol)
        {
            switch (protocol)
            {
                case ConnectionProtocol.Ssh:
                    return "SSH";
                case ConnectionProtocol.Telnet:
                    return "Telnet";
                case ConnectionProtocol.Serial:
                    return "串口";
                case ConnectionProtocol.WinRm:
                    return "Windows 远程";
            }
        }

        if (value is SshAuthenticationMethod authenticationMethod)
        {
            switch (authenticationMethod)
            {
                case SshAuthenticationMethod.Password:
                    return "密码验证";
                case SshAuthenticationMethod.PrivateKey:
                    return "PuTTY PPK 私钥";
            }
        }

        return "未知";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
