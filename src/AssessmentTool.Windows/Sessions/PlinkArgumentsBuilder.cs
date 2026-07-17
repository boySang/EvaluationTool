using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Processes;

namespace AssessmentTool.Windows.Sessions;

internal sealed class PlinkArgumentsBuildRequest
{
    internal PlinkArgumentsBuildRequest(
        ConnectionProfile profile,
        string? passwordFilePath,
        string? privateKeyPath)
    {
        Profile = profile ?? throw new ArgumentNullException(nameof(profile));
        PasswordFilePath = passwordFilePath;
        PrivateKeyPath = privateKeyPath;
    }

    internal ConnectionProfile Profile { get; }
    internal string? PasswordFilePath { get; }
    internal string? PrivateKeyPath { get; }
}

internal sealed class PlinkArgumentsBuilder
{
    internal sealed class LaunchPlan : ProcessArgumentPlan, IControlledPlinkArgumentPlan
    {
        private LaunchPlan(IReadOnlyList<string> argumentTokens)
            : base(argumentTokens)
        {
        }

        internal static LaunchPlan Create(PlinkArgumentsBuildRequest request)
        {
            return new LaunchPlan(BuildArgumentTokens(request));
        }
    }

    internal LaunchPlan Build(PlinkArgumentsBuildRequest request)
    {
        return LaunchPlan.Create(request);
    }

    private static IReadOnlyList<string> BuildArgumentTokens(PlinkArgumentsBuildRequest request)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var profile = request.Profile;
        if (profile.Protocol != ConnectionProtocol.Ssh)
        {
            throw new InvalidOperationException("Plink 参数生成器仅支持 SSH 连接配置。");
        }

        var options = profile.SshOptions;
        if (options == null)
        {
            throw new InvalidOperationException("SSH 连接配置不完整，已阻止自动连接。");
        }

        if (options.JumpHost != null)
        {
            throw new NotSupportedException("当前版本未启用经验证跳板机，已阻止直接连接目标设备。");
        }

        ValidateHost(profile.Host, nameof(profile.Host));
        ValidatePort(profile.Port);
        ValidateEndpointBinding(profile, options);
        ValidateUserName(options.UserName);
        ValidateCredentialReferences(options);
        var fingerprint = ValidateHostKeyTrust(options.HostKeyTrust);
        var authenticationTokens = BuildAuthenticationTokens(options, request);

        var tokens = new List<string>
        {
            "-ssh",
            "-batch",
            "-no-antispoof",
            "-P",
            profile.Port.ToString(CultureInfo.InvariantCulture),
            "-l",
            options.UserName,
            "-hostkey",
            fingerprint
        };
        tokens.AddRange(authenticationTokens);
        tokens.Add(profile.Host);

        return new ReadOnlyCollection<string>(tokens);
    }

    private static IReadOnlyList<string> BuildAuthenticationTokens(
        SshConnectionOptions options,
        PlinkArgumentsBuildRequest request)
    {
        switch (options.AuthenticationMethod)
        {
            case SshAuthenticationMethod.Password:
                if (request.PrivateKeyPath != null)
                {
                    throw new ArgumentException("密码认证不能提供私钥文件路径。", nameof(request));
                }

                return new[]
                {
                    "-pwfile",
                    ValidateControlledLocalPath(request.PasswordFilePath, "密码临时文件路径")
                };
            case SshAuthenticationMethod.PrivateKey:
                if (request.PasswordFilePath != null)
                {
                    throw new ArgumentException("私钥认证不能把口令文件加入 Plink 参数。", nameof(request));
                }

                return new[]
                {
                    "-i",
                    ValidateControlledLocalPath(request.PrivateKeyPath, "私钥临时文件路径")
                };
            default:
                throw new InvalidOperationException("SSH 认证方式无效，已阻止自动连接。");
        }
    }

    private static void ValidateCredentialReferences(SshConnectionOptions options)
    {
        try
        {
            _ = options.CredentialReference.Value;
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidOperationException("SSH 凭据引用无效，已阻止自动连接。", exception);
        }

        if (options.AuthenticationMethod == SshAuthenticationMethod.Password)
        {
            if (options.PrivateKeyReference.HasValue)
            {
                throw new InvalidOperationException("密码认证配置不能包含私钥引用。");
            }

            return;
        }

        if (options.AuthenticationMethod != SshAuthenticationMethod.PrivateKey ||
            !options.PrivateKeyReference.HasValue)
        {
            throw new InvalidOperationException("私钥认证配置缺少有效私钥引用。");
        }

        try
        {
            _ = options.PrivateKeyReference.Value.Value;
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidOperationException("私钥引用无效，已阻止自动连接。", exception);
        }
    }

    private static string ValidateHostKeyTrust(HostKeyTrust trust)
    {
        if (trust == null)
        {
            throw new InvalidOperationException("SSH 主机指纹信任缺失，已阻止自动连接。");
        }

        if (trust.State != HostKeyTrustState.Pinned && trust.State != HostKeyTrustState.Verified)
        {
            throw new InvalidOperationException("SSH 主机指纹尚未确认或已发生变化，已阻止自动连接。");
        }

        var algorithm = ValidateSafeToken(
            trust.Algorithm,
            "SSH 主机密钥算法",
            allowSpaces: false);
        var fingerprint = ValidateSafeToken(
            trust.Fingerprint,
            "SSH 主机指纹",
            allowSpaces: true);
        if (!fingerprint.StartsWith(algorithm + " ", StringComparison.Ordinal) ||
            fingerprint.Length <= algorithm.Length + 1 ||
            !string.Equals(fingerprint, fingerprint.Trim(), StringComparison.Ordinal))
        {
            throw new InvalidOperationException("SSH 主机指纹不是与算法匹配的完整 Plink 指纹，已阻止自动连接。");
        }

        return fingerprint;
    }

    private static void ValidateHost(string host, string parameterName)
    {
        host = ValidateSafeToken(host, "SSH 主机", allowSpaces: false);

        IPAddress? address;
        if (IPAddress.TryParse(host, out address))
        {
            if (address.AddressFamily == AddressFamily.InterNetworkV6 ||
                (address.AddressFamily == AddressFamily.InterNetwork && IsStrictIpv4(host)))
            {
                return;
            }
        }

        if (!IsDnsHostName(host))
        {
            throw new ArgumentException("SSH 主机必须是有效的 DNS 名称、IPv4 或 IPv6 字面量。", parameterName);
        }
    }

    private static void ValidatePort(int port)
    {
        if (port < 1 || port > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "SSH 端口必须在 1 到 65535 之间。");
        }
    }

    private static void ValidateEndpointBinding(
        ConnectionProfile profile,
        SshConnectionOptions options)
    {
        var actualEndpoint = new SshEndpointIdentity(profile.Host, profile.Port);
        if (!actualEndpoint.Equals(options.Endpoint) ||
            !actualEndpoint.Equals(options.HostKeyTrust.Endpoint))
        {
            throw new InvalidOperationException("SSH 主机指纹信任与实际连接端点不一致，已阻止自动连接。");
        }
    }

    private static void ValidateUserName(string userName)
    {
        ValidateSafeToken(userName, "SSH 用户名", allowSpaces: false);
    }

    private static string ValidateSafeToken(string? value, string description, bool allowSpaces)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(description + "不能为空。", description);
        }

        if (value![0] == '-')
        {
            throw new ArgumentException(description + "不能以 '-' 开头。", description);
        }

        foreach (var character in value)
        {
            if (char.IsControl(character) || character == '\'' || character == '"' ||
                character == '/' || character == '\\')
            {
                throw new ArgumentException(description + "包含不安全字符。", description);
            }

            if (!allowSpaces && char.IsWhiteSpace(character))
            {
                throw new ArgumentException(description + "不能包含空白字符。", description);
            }
        }

        return value;
    }

    private static string ValidateControlledLocalPath(string? path, string description)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException(description + "不能为空。", description);
        }

        if (path!.Length < 4 ||
            !IsAsciiLetter(path[0]) ||
            path[1] != ':' ||
            path[2] != '\\')
        {
            throw new ArgumentException(description + "必须是带盘符的完全限定本地 Windows 路径。", description);
        }

        if (path.IndexOf('/') >= 0 ||
            path.IndexOf(':', 2) >= 0)
        {
            throw new ArgumentException(description + "不能是 UNC、设备、ADS 或混合分隔符路径。", description);
        }

        foreach (var character in path)
        {
            if (char.IsControl(character) || character == '\'' || character == '"')
            {
                throw new ArgumentException(description + "包含控制字符或引号。", description);
            }
        }

        var segments = path.Substring(3).Split('\\');
        if (segments.Length == 0)
        {
            throw new ArgumentException(description + "必须指向文件。", description);
        }

        foreach (var segment in segments)
        {
            ValidateSafePathSegment(segment, description);
        }

        return path;
    }

    private static void ValidateSafePathSegment(string segment, string description)
    {
        if (segment.Length == 0 ||
            segment == "." ||
            segment == ".." ||
            segment[segment.Length - 1] == '.' ||
            segment[segment.Length - 1] == ' ')
        {
            throw new ArgumentException(description + "必须是规范路径，不能包含空段、跳转段或尾随点和空格。", description);
        }

        foreach (var character in segment)
        {
            if (character == '<' || character == '>' || character == ':' || character == '"' ||
                character == '/' || character == '|' || character == '?' || character == '*')
            {
                throw new ArgumentException(description + "包含 Windows 文件名不允许的字符。", description);
            }
        }

        var extensionSeparator = segment.IndexOf('.');
        var baseName = extensionSeparator >= 0 ? segment.Substring(0, extensionSeparator) : segment;
        if (IsReservedDosDeviceName(baseName))
        {
            throw new ArgumentException(description + "不能指向 Windows 保留设备名。", description);
        }
    }

    private static bool IsReservedDosDeviceName(string value)
    {
        if (string.Equals(value, "CON", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "PRN", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "AUX", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "NUL", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "CLOCK$", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return value.Length == 4 &&
            (value.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
             value.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
            value[3] >= '1' && value[3] <= '9';
    }

    private static bool IsStrictIpv4(string value)
    {
        var parts = value.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length == 0 || (part.Length > 1 && part[0] == '0'))
            {
                return false;
            }

            int octet;
            if (!int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out octet) ||
                octet < 0 || octet > 255)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsDnsHostName(string value)
    {
        var dnsValue = value.EndsWith(".", StringComparison.Ordinal)
            ? value.Substring(0, value.Length - 1)
            : value;
        if (dnsValue.Length == 0 || dnsValue.Length > 253)
        {
            return false;
        }

        var labels = dnsValue.Split('.');
        foreach (var label in labels)
        {
            if (label.Length == 0 || label.Length > 63 ||
                label[0] == '-' || label[label.Length - 1] == '-')
            {
                return false;
            }

            foreach (var character in label)
            {
                if (!IsAsciiLetter(character) &&
                    (character < '0' || character > '9') &&
                    character != '-')
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool IsAsciiLetter(char value)
    {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
    }
}
