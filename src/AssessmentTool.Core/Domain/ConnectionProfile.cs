using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;

namespace AssessmentTool.Core.Domain;

public enum ConnectionProtocol
{
    Ssh,
    Telnet,
    Serial,
    WinRm
}

public enum TargetCategory
{
    Automatic,
    NetworkDevice,
    Server,
    Database,
    Middleware,
    SecurityDevice
}

public enum SshAuthenticationMethod
{
    Password,
    PrivateKey
}

public enum HostKeyTrustState
{
    Unconfigured,
    AwaitingProbe,
    AwaitingConfirmation,
    Pinned,
    Verified,
    MismatchBlocked
}

public sealed class SshEndpointIdentity : IEquatable<SshEndpointIdentity>
{
    public SshEndpointIdentity(string host, int port)
    {
        Host = SshContractValidation.NormalizeHost(host, nameof(host));
        Port = SshContractValidation.ValidatePort(port, nameof(port));
    }

    public string Host { get; }
    public int Port { get; }
    public ConnectionProtocol Protocol => ConnectionProtocol.Ssh;

    public bool Equals(SshEndpointIdentity? other)
    {
        return other != null &&
               Port == other.Port &&
               string.Equals(Host, other.Host, StringComparison.Ordinal);
    }

    public override bool Equals(object? obj)
    {
        return Equals(obj as SshEndpointIdentity);
    }

    public override int GetHashCode()
    {
        unchecked
        {
            return (StringComparer.Ordinal.GetHashCode(Host) * 397) ^ Port;
        }
    }

    public override string ToString()
    {
        return Host.IndexOf(':') >= 0
            ? "[" + Host + "]:" + Port
            : Host + ":" + Port;
    }
}

public readonly struct PrivateKeyReference : IEquatable<PrivateKeyReference>
{
    private readonly Guid value;

    private PrivateKeyReference(Guid value)
    {
        this.value = value;
    }

    public Guid Value
    {
        get
        {
            if (value == Guid.Empty)
            {
                throw new InvalidOperationException(nameof(PrivateKeyReference) + " 尚未初始化。");
            }

            return value;
        }
    }

    internal bool IsValid => value != Guid.Empty;

    public static PrivateKeyReference New()
    {
        return new PrivateKeyReference(Guid.NewGuid());
    }

    public static PrivateKeyReference Parse(string value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value), "私钥引用不能为空。");
        }

        Guid parsed;
        if (!Guid.TryParseExact(value, "D", out parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("私钥引用必须是 D 格式的非空不透明 GUID，不能使用文件路径或私钥内容。", nameof(value));
        }

        return new PrivateKeyReference(parsed);
    }

    public bool Equals(PrivateKeyReference other)
    {
        return value.Equals(other.value);
    }

    public override bool Equals(object? obj)
    {
        return obj is PrivateKeyReference other && Equals(other);
    }

    public override int GetHashCode()
    {
        return value.GetHashCode();
    }

    public override string ToString()
    {
        return Value.ToString("D");
    }
}

public enum HostKeyTrustAuditEventKind
{
    InitialPin,
    MatchingVerification,
    MismatchObserved,
    Reconfirmed
}

public sealed class HostKeyTrustAuditEvent
{
    internal HostKeyTrustAuditEvent(
        HostKeyTrustAuditEventKind kind,
        SshEndpointIdentity endpoint,
        string algorithm,
        string fingerprint,
        DateTimeOffset occurredAt,
        string source)
    {
        Kind = kind;
        Endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint), "SSH 端点身份不能为空。");
        Algorithm = SshContractValidation.ValidateAlgorithm(algorithm, nameof(algorithm));
        Fingerprint = SshContractValidation.ValidateFingerprint(fingerprint, Algorithm, nameof(fingerprint));
        OccurredAt = occurredAt.ToUniversalTime();
        Source = SshContractValidation.ValidateAuditText(source, nameof(source));
    }

    public HostKeyTrustAuditEventKind Kind { get; }
    public SshEndpointIdentity Endpoint { get; }
    public string Algorithm { get; }
    public string Fingerprint { get; }
    public DateTimeOffset OccurredAt { get; }
    public string Source { get; }
}

public sealed class HostKeyTrust
{
    private HostKeyTrust(
        SshEndpointIdentity endpoint,
        HostKeyTrustState state,
        string? algorithm,
        string? fingerprint,
        string? observedAlgorithm,
        string? observedFingerprint,
        DateTimeOffset? observedAt,
        DateTimeOffset? confirmedAt,
        string? confirmationSource,
        string? previousAlgorithm,
        string? previousFingerprint,
        DateTimeOffset? previousConfirmedAt,
        string? previousConfirmationSource,
        IReadOnlyList<HostKeyTrustAuditEvent> auditHistory)
    {
        Endpoint = endpoint;
        State = state;
        Algorithm = algorithm;
        Fingerprint = fingerprint;
        ObservedAlgorithm = observedAlgorithm;
        ObservedFingerprint = observedFingerprint;
        ObservedAt = observedAt?.ToUniversalTime();
        ConfirmedAt = confirmedAt?.ToUniversalTime();
        ConfirmationSource = confirmationSource;
        PreviousAlgorithm = previousAlgorithm;
        PreviousFingerprint = previousFingerprint;
        PreviousConfirmedAt = previousConfirmedAt?.ToUniversalTime();
        PreviousConfirmationSource = previousConfirmationSource;
        AuditHistory = CopyAuditHistory(auditHistory);
    }

    public SshEndpointIdentity Endpoint { get; }
    public HostKeyTrustState State { get; }
    public string? Algorithm { get; }
    public string? Fingerprint { get; }
    public string? ObservedAlgorithm { get; }
    public string? ObservedFingerprint { get; }
    public DateTimeOffset? ObservedAt { get; }
    public DateTimeOffset? ConfirmedAt { get; }
    public string? ConfirmationSource { get; }
    public string? PreviousAlgorithm { get; }
    public string? PreviousFingerprint { get; }
    public DateTimeOffset? PreviousConfirmedAt { get; }
    public string? PreviousConfirmationSource { get; }
    public IReadOnlyList<HostKeyTrustAuditEvent> AuditHistory { get; }
    /// <summary>
    /// Pinned and Verified both retain the same immutable endpoint and pinned fingerprint.
    /// Verified only records that the latest connection revalidated that existing pin.
    /// </summary>
    public bool IsEligibleForAutomaticConnection =>
        State == HostKeyTrustState.Pinned || State == HostKeyTrustState.Verified;

    public static HostKeyTrust Unconfigured(SshEndpointIdentity endpoint)
    {
        return new HostKeyTrust(
            RequireEndpoint(endpoint),
            HostKeyTrustState.Unconfigured,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            Array.Empty<HostKeyTrustAuditEvent>());
    }

    internal HostKeyTrust BeginProbeInternal()
    {
        if (State != HostKeyTrustState.Unconfigured)
        {
            throw new InvalidOperationException("只有未配置的 SSH 端点才能开始主机指纹探测。");
        }

        return Copy(HostKeyTrustState.AwaitingProbe);
    }

    internal HostKeyTrust RecordObservationInternal(
        string algorithm,
        string fingerprint,
        DateTimeOffset observedAt)
    {
        if (State != HostKeyTrustState.AwaitingProbe)
        {
            throw new InvalidOperationException("只有等待探测的 SSH 端点才能记录主机指纹观察值。");
        }

        return CreateAwaitingConfirmation(Endpoint, algorithm, fingerprint, observedAt);
    }

    internal HostKeyTrust RecordMatchingObservationInternal(DateTimeOffset observedAt)
    {
        EnsurePinnedState("只有已固定或已验证的 SSH 主机指纹才能记录验证结果。");
        EnsureObservationNotBeforeConfirmation(observedAt);

        return new HostKeyTrust(
            Endpoint,
            HostKeyTrustState.Verified,
            Algorithm,
            Fingerprint,
            Algorithm,
            Fingerprint,
            observedAt,
            ConfirmedAt,
            ConfirmationSource,
            PreviousAlgorithm,
            PreviousFingerprint,
            PreviousConfirmedAt,
            PreviousConfirmationSource,
            AppendAuditEvent(new HostKeyTrustAuditEvent(
                HostKeyTrustAuditEventKind.MatchingVerification,
                Endpoint,
                Algorithm!,
                Fingerprint!,
                observedAt,
                "SSH 主机密钥探测（匹配）")));
    }

    internal HostKeyTrust RecordMismatchObservationInternal(
        string observedAlgorithm,
        string observedFingerprint,
        DateTimeOffset observedAt)
    {
        EnsurePinnedState("只有已固定或已验证的 SSH 主机指纹才能记录不匹配阻断。");
        EnsureObservationNotBeforeConfirmation(observedAt);

        var validatedAlgorithm = SshContractValidation.ValidateAlgorithm(
            observedAlgorithm,
            nameof(observedAlgorithm));
        var validatedFingerprint = SshContractValidation.ValidateFingerprint(
            observedFingerprint,
            validatedAlgorithm,
            nameof(observedFingerprint));
        if (string.Equals(Algorithm, validatedAlgorithm, StringComparison.Ordinal) &&
            string.Equals(Fingerprint, validatedFingerprint, StringComparison.Ordinal))
        {
            throw new ArgumentException("观察到的 SSH 主机指纹与已固定指纹相同，不能记录为不匹配。", nameof(observedFingerprint));
        }

        return new HostKeyTrust(
            Endpoint,
            HostKeyTrustState.MismatchBlocked,
            Algorithm,
            Fingerprint,
            validatedAlgorithm,
            validatedFingerprint,
            observedAt,
            ConfirmedAt,
            ConfirmationSource,
            PreviousAlgorithm,
            PreviousFingerprint,
            PreviousConfirmedAt,
            PreviousConfirmationSource,
            AppendAuditEvent(new HostKeyTrustAuditEvent(
                HostKeyTrustAuditEventKind.MismatchObserved,
                Endpoint,
                validatedAlgorithm,
                validatedFingerprint,
                observedAt,
                "SSH 主机密钥探测（不匹配）")));
    }

    internal HostKeyTrust BeginReconfirmationInternal()
    {
        if (State != HostKeyTrustState.MismatchBlocked)
        {
            throw new InvalidOperationException("只有已阻断的指纹不匹配才能由用户发起重新确认。");
        }

        return Copy(HostKeyTrustState.AwaitingConfirmation);
    }

    internal HostKeyTrust ConfirmInternal(DateTimeOffset confirmedAt, string confirmationSource)
    {
        if (State != HostKeyTrustState.AwaitingConfirmation ||
            ObservedAlgorithm == null ||
            ObservedFingerprint == null ||
            !ObservedAt.HasValue)
        {
            throw new InvalidOperationException("只有包含完整观察值的待确认指纹才能通过确认服务固定。");
        }

        if (confirmedAt < ObservedAt.Value)
        {
            throw new ArgumentOutOfRangeException(nameof(confirmedAt), confirmedAt, "确认时间不能早于观察时间。");
        }

        var validatedSource = SshContractValidation.ValidateAuditText(
            confirmationSource,
            nameof(confirmationSource));
        var isReplacement = Algorithm != null && Fingerprint != null;
        var auditEvent = new HostKeyTrustAuditEvent(
            isReplacement ? HostKeyTrustAuditEventKind.Reconfirmed : HostKeyTrustAuditEventKind.InitialPin,
            Endpoint,
            ObservedAlgorithm,
            ObservedFingerprint,
            confirmedAt,
            validatedSource);
        return new HostKeyTrust(
            Endpoint,
            HostKeyTrustState.Pinned,
            ObservedAlgorithm,
            ObservedFingerprint,
            ObservedAlgorithm,
            ObservedFingerprint,
            ObservedAt,
            confirmedAt,
            validatedSource,
            isReplacement ? Algorithm : PreviousAlgorithm,
            isReplacement ? Fingerprint : PreviousFingerprint,
            isReplacement ? ConfirmedAt : PreviousConfirmedAt,
            isReplacement ? ConfirmationSource : PreviousConfirmationSource,
            AppendAuditEvent(auditEvent));
    }

    private void EnsurePinnedState(string message)
    {
        if (State != HostKeyTrustState.Pinned && State != HostKeyTrustState.Verified)
        {
            throw new InvalidOperationException(message);
        }
    }

    private void EnsureObservationNotBeforeConfirmation(DateTimeOffset observedAt)
    {
        if (ConfirmedAt.HasValue && observedAt < ConfirmedAt.Value)
        {
            throw new ArgumentOutOfRangeException(nameof(observedAt), observedAt, "观察时间不能早于指纹确认时间。");
        }
    }

    private static HostKeyTrust CreateAwaitingConfirmation(
        SshEndpointIdentity endpoint,
        string algorithm,
        string fingerprint,
        DateTimeOffset observedAt)
    {
        var validatedAlgorithm = SshContractValidation.ValidateAlgorithm(algorithm, nameof(algorithm));
        var validatedFingerprint = SshContractValidation.ValidateFingerprint(
            fingerprint,
            validatedAlgorithm,
            nameof(fingerprint));

        return new HostKeyTrust(
            endpoint,
            HostKeyTrustState.AwaitingConfirmation,
            null,
            null,
            validatedAlgorithm,
            validatedFingerprint,
            observedAt,
            null,
            null,
            null,
            null,
            null,
            null,
            Array.Empty<HostKeyTrustAuditEvent>());
    }

    private HostKeyTrust Copy(HostKeyTrustState state)
    {
        return new HostKeyTrust(
            Endpoint,
            state,
            Algorithm,
            Fingerprint,
            ObservedAlgorithm,
            ObservedFingerprint,
            ObservedAt,
            ConfirmedAt,
            ConfirmationSource,
            PreviousAlgorithm,
            PreviousFingerprint,
            PreviousConfirmedAt,
            PreviousConfirmationSource,
            AuditHistory);
    }

    private IReadOnlyList<HostKeyTrustAuditEvent> AppendAuditEvent(HostKeyTrustAuditEvent auditEvent)
    {
        var events = new List<HostKeyTrustAuditEvent>(AuditHistory.Count + 1);
        for (var index = 0; index < AuditHistory.Count; index++)
        {
            events.Add(AuditHistory[index]);
        }

        events.Add(auditEvent);
        return events.AsReadOnly();
    }

    private static IReadOnlyList<HostKeyTrustAuditEvent> CopyAuditHistory(
        IReadOnlyList<HostKeyTrustAuditEvent> auditHistory)
    {
        if (auditHistory == null)
        {
            throw new ArgumentNullException(nameof(auditHistory));
        }

        var events = new List<HostKeyTrustAuditEvent>(auditHistory.Count);
        for (var index = 0; index < auditHistory.Count; index++)
        {
            events.Add(auditHistory[index]);
        }

        return new ReadOnlyCollection<HostKeyTrustAuditEvent>(events);
    }

    private static SshEndpointIdentity RequireEndpoint(SshEndpointIdentity endpoint)
    {
        return endpoint ?? throw new ArgumentNullException(nameof(endpoint), "SSH 端点身份不能为空。");
    }
}

public static class HostKeyTrustServices
{
    public static HostKeyTrustCoordinator CreateCoordinator()
    {
        return new HostKeyTrustCoordinator();
    }
}

public sealed class HostKeyTrustCoordinator
{
    internal HostKeyTrustCoordinator()
    {
    }

    public HostKeyTrust BeginProbe(HostKeyTrust unconfigured)
    {
        return RequireTrust(unconfigured, nameof(unconfigured)).BeginProbeInternal();
    }

    public HostKeyTrust RecordObservation(
        HostKeyTrust awaitingProbe,
        string algorithm,
        string fingerprint,
        DateTimeOffset observedAt)
    {
        return RequireTrust(awaitingProbe, nameof(awaitingProbe))
            .RecordObservationInternal(algorithm, fingerprint, observedAt);
    }

    public HostKeyTrust RecordMatchingObservation(HostKeyTrust pinned, DateTimeOffset observedAt)
    {
        return RequireTrust(pinned, nameof(pinned)).RecordMatchingObservationInternal(observedAt);
    }

    public HostKeyTrust RecordMismatchObservation(
        HostKeyTrust pinned,
        string observedAlgorithm,
        string observedFingerprint,
        DateTimeOffset observedAt)
    {
        return RequireTrust(pinned, nameof(pinned)).RecordMismatchObservationInternal(
            observedAlgorithm,
            observedFingerprint,
            observedAt);
    }

    public HostKeyTrust BeginReconfirmation(HostKeyTrust mismatchBlocked)
    {
        return RequireTrust(mismatchBlocked, nameof(mismatchBlocked)).BeginReconfirmationInternal();
    }

    public HostKeyTrust Confirm(
        HostKeyTrust awaitingConfirmation,
        DateTimeOffset confirmedAt,
        string confirmationSource)
    {
        if (awaitingConfirmation == null)
        {
            throw new ArgumentNullException(nameof(awaitingConfirmation), "待确认的 SSH 主机指纹不能为空。");
        }

        return awaitingConfirmation.ConfirmInternal(confirmedAt, confirmationSource);
    }

    private static HostKeyTrust RequireTrust(HostKeyTrust trust, string parameterName)
    {
        return trust ?? throw new ArgumentNullException(parameterName, "SSH 主机指纹信任不能为空。");
    }
}

public sealed class SshConnectionOptions
{
    public SshConnectionOptions(
        string userName,
        SshAuthenticationMethod authenticationMethod,
        CredentialReference credentialReference,
        PrivateKeyReference? privateKeyReference,
        HostKeyTrust hostKeyTrust,
        SshHop? jumpHost = null)
        : this(
            RequireTrust(hostKeyTrust).Endpoint,
            userName,
            authenticationMethod,
            credentialReference,
            privateKeyReference,
            hostKeyTrust,
            jumpHost)
    {
    }

    public SshConnectionOptions(
        SshEndpointIdentity endpoint,
        string userName,
        SshAuthenticationMethod authenticationMethod,
        CredentialReference credentialReference,
        PrivateKeyReference? privateKeyReference,
        HostKeyTrust hostKeyTrust,
        SshHop? jumpHost = null)
    {
        Endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint), "SSH 端点身份不能为空。");
        UserName = SshContractValidation.ValidateUserName(userName, nameof(userName));
        SshContractValidation.ValidateAuthentication(
            authenticationMethod,
            credentialReference,
            privateKeyReference);

        AuthenticationMethod = authenticationMethod;
        CredentialReference = credentialReference;
        PrivateKeyReference = privateKeyReference;
        HostKeyTrust = RequireTrust(hostKeyTrust);
        if (!Endpoint.Equals(HostKeyTrust.Endpoint))
        {
            throw new ArgumentException("SSH 主机指纹信任与连接选项的规范化端点不一致。", nameof(hostKeyTrust));
        }

        JumpHost = jumpHost;
    }

    public SshEndpointIdentity Endpoint { get; }
    public string UserName { get; }
    public SshAuthenticationMethod AuthenticationMethod { get; }
    public CredentialReference CredentialReference { get; }
    public PrivateKeyReference? PrivateKeyReference { get; }
    public HostKeyTrust HostKeyTrust { get; }
    public SshHop? JumpHost { get; }

    private static HostKeyTrust RequireTrust(HostKeyTrust hostKeyTrust)
    {
        return hostKeyTrust ?? throw new ArgumentNullException(
            nameof(hostKeyTrust),
            "SSH 主机指纹信任不能为空。");
    }
}

public sealed class SshHop
{
    public SshHop(
        string host,
        int port,
        string userName,
        SshAuthenticationMethod authenticationMethod,
        CredentialReference credentialReference,
        PrivateKeyReference? privateKeyReference,
        HostKeyTrust hostKeyTrust)
    {
        Endpoint = new SshEndpointIdentity(host, port);
        Host = Endpoint.Host;
        Port = Endpoint.Port;
        UserName = SshContractValidation.ValidateUserName(userName, nameof(userName));
        SshContractValidation.ValidateAuthentication(
            authenticationMethod,
            credentialReference,
            privateKeyReference);

        AuthenticationMethod = authenticationMethod;
        CredentialReference = credentialReference;
        PrivateKeyReference = privateKeyReference;
        HostKeyTrust = hostKeyTrust ?? throw new ArgumentNullException(
            nameof(hostKeyTrust),
            "跳板机的 SSH 主机指纹信任不能为空。");
        if (!Endpoint.Equals(HostKeyTrust.Endpoint))
        {
            throw new ArgumentException("跳板机主机指纹信任与跳板机规范化端点不一致。", nameof(hostKeyTrust));
        }
    }

    public SshEndpointIdentity Endpoint { get; }
    public string Host { get; }
    public int Port { get; }
    public string UserName { get; }
    public SshAuthenticationMethod AuthenticationMethod { get; }
    public CredentialReference CredentialReference { get; }
    public PrivateKeyReference? PrivateKeyReference { get; }
    public HostKeyTrust HostKeyTrust { get; }
}

public sealed class ConnectionProfile
{
    public ConnectionProfile(string displayName, string host, int port, ConnectionProtocol protocol)
        : this(displayName, host, port, protocol, null)
    {
    }

    public ConnectionProfile(
        string displayName,
        string host,
        int port,
        ConnectionProtocol protocol,
        SshConnectionOptions? sshOptions)
    {
        if (!Enum.IsDefined(typeof(ConnectionProtocol), protocol))
        {
            throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "连接协议无效。");
        }

        if (protocol != ConnectionProtocol.Ssh && sshOptions != null)
        {
            throw new ArgumentException("SSH 连接选项仅 SSH 协议可以使用。", nameof(sshOptions));
        }

        DisplayName = SshContractValidation.ValidateRequiredText(displayName, nameof(displayName), "显示名称不能为空。");
        Port = SshContractValidation.ValidatePort(port, nameof(port));
        Protocol = protocol;
        if (protocol == ConnectionProtocol.Ssh)
        {
            SshEndpoint = new SshEndpointIdentity(host, Port);
            Host = SshEndpoint.Host;
            if (sshOptions != null && !SshEndpoint.Equals(sshOptions.Endpoint))
            {
                throw new ArgumentException("SSH 连接选项与连接资料的规范化端点不一致。", nameof(sshOptions));
            }
        }
        else
        {
            Host = SshContractValidation.ValidateHost(host, nameof(host));
        }

        SshOptions = sshOptions;
        TargetCategory = TargetCategory.Automatic;
    }

    public string DisplayName { get; }
    public string Host { get; }
    public int Port { get; }
    public ConnectionProtocol Protocol { get; }
    public SshEndpointIdentity? SshEndpoint { get; }
    public TargetCategory TargetCategory { get; set; }
    public SshConnectionOptions? SshOptions { get; }
    public bool IsEligibleForAutomaticConnection =>
        Protocol != ConnectionProtocol.Ssh ||
        (SshOptions != null &&
         SshOptions.JumpHost == null &&
         SshOptions.HostKeyTrust.IsEligibleForAutomaticConnection);
}

internal static class SshContractValidation
{
    public static string ValidateRequiredText(string value, string parameterName, string errorMessage)
    {
        if (value == null)
        {
            throw new ArgumentNullException(parameterName, errorMessage);
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(errorMessage, parameterName);
        }

        if (ContainsControlCharacter(value))
        {
            throw new ArgumentException("文本不能包含控制字符。", parameterName);
        }

        return value;
    }

    public static string ValidateHost(string value, string parameterName)
    {
        value = ValidateSafeToken(value, parameterName, allowSpaces: false, "主机名不能为空。");

        IPAddress address;
        if (IPAddress.TryParse(value, out address))
        {
            if (address.AddressFamily == AddressFamily.InterNetworkV6 && value.IndexOf(':') >= 0)
            {
                return value;
            }

            if (address.AddressFamily == AddressFamily.InterNetwork && IsStrictIpv4(value))
            {
                return value;
            }
        }

        if (!IsDnsHostName(value))
        {
            throw new ArgumentException("主机必须是有效的 DNS 名称、IPv4 或 IPv6 字面量。", parameterName);
        }

        return value;
    }

    public static string NormalizeHost(string value, string parameterName)
    {
        value = ValidateHost(value, parameterName);

        IPAddress address;
        if (IPAddress.TryParse(value, out address))
        {
            return address.ToString().ToLowerInvariant();
        }

        return value.EndsWith(".", StringComparison.Ordinal)
            ? value.Substring(0, value.Length - 1).ToLowerInvariant()
            : value.ToLowerInvariant();
    }

    public static string ValidateUserName(string value, string parameterName)
    {
        return ValidateSafeToken(value, parameterName, allowSpaces: false, "SSH 用户名不能为空。");
    }

    public static string ValidateAlgorithm(string value, string parameterName)
    {
        return ValidateSafeToken(value, parameterName, allowSpaces: false, "SSH 主机密钥算法不能为空。");
    }

    public static string ValidateFingerprint(string value, string algorithm, string parameterName)
    {
        value = ValidateSafeToken(value, parameterName, allowSpaces: true, "SSH 主机指纹不能为空。");
        if (!string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            !value.StartsWith(algorithm + " ", StringComparison.Ordinal) ||
            value.Length <= algorithm.Length + 1)
        {
            throw new ArgumentException("SSH 主机指纹必须是与算法匹配的 Plink 完整指纹。", parameterName);
        }

        return value;
    }

    public static int ValidatePort(int port, string parameterName)
    {
        if (port < 1 || port > 65535)
        {
            throw new ArgumentOutOfRangeException(parameterName, port, "端口必须在 1 到 65535 之间。");
        }

        return port;
    }

    public static string ValidateAuditText(string value, string parameterName)
    {
        return ValidateRequiredText(value, parameterName, "确认来源不能为空。");
    }

    public static void ValidateAuthentication(
        SshAuthenticationMethod authenticationMethod,
        CredentialReference credentialReference,
        PrivateKeyReference? privateKeyReference)
    {
        if (!Enum.IsDefined(typeof(SshAuthenticationMethod), authenticationMethod))
        {
            throw new ArgumentOutOfRangeException(
                nameof(authenticationMethod),
                authenticationMethod,
                "SSH 认证方式无效。");
        }

        if (!credentialReference.IsValid)
        {
            throw new ArgumentException("凭据引用必须是已初始化的不透明引用。", nameof(credentialReference));
        }

        if (authenticationMethod == SshAuthenticationMethod.Password && privateKeyReference.HasValue)
        {
            throw new ArgumentException("密码认证不能携带私钥引用。", nameof(privateKeyReference));
        }

        if (authenticationMethod == SshAuthenticationMethod.PrivateKey &&
            (!privateKeyReference.HasValue || !privateKeyReference.Value.IsValid))
        {
            throw new ArgumentException("私钥认证必须提供已初始化的不透明私钥引用。", nameof(privateKeyReference));
        }
    }

    private static string ValidateSafeToken(
        string value,
        string parameterName,
        bool allowSpaces,
        string blankMessage)
    {
        value = ValidateRequiredText(value, parameterName, blankMessage);
        if (value[0] == '-')
        {
            throw new ArgumentException("该值不能以 '-' 开头。", parameterName);
        }

        foreach (var character in value)
        {
            if (character == '\'' || character == '"' || character == '/' || character == '\\')
            {
                throw new ArgumentException("该值不能包含引号或路径分隔符。", parameterName);
            }

            if (!allowSpaces && char.IsWhiteSpace(character))
            {
                throw new ArgumentException("该值不能包含空白字符。", parameterName);
            }
        }

        return value;
    }

    private static bool ContainsControlCharacter(string value)
    {
        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                return true;
            }
        }

        return false;
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
            if (!int.TryParse(part, out octet) || octet < 0 || octet > 255)
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
            if (label.Length == 0 || label.Length > 63 || label[0] == '-' || label[label.Length - 1] == '-')
            {
                return false;
            }

            foreach (var character in label)
            {
                var isAsciiLetter =
                    (character >= 'a' && character <= 'z') ||
                    (character >= 'A' && character <= 'Z');
                var isAsciiDigit = character >= '0' && character <= '9';
                if (!isAsciiLetter && !isAsciiDigit && character != '-')
                {
                    return false;
                }
            }
        }

        return true;
    }
}
