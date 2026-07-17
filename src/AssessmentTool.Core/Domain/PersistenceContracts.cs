using System;

namespace AssessmentTool.Core.Domain;

public readonly struct ProjectId : IEquatable<ProjectId>
{
    private readonly Guid value;

    private ProjectId(Guid value)
    {
        this.value = value;
    }

    public Guid Value => RequireValue(value, nameof(ProjectId));

    internal bool IsValid => value != Guid.Empty;

    public static ProjectId New()
    {
        return new ProjectId(Guid.NewGuid());
    }

    public static ProjectId Parse(string value)
    {
        return new ProjectId(ParseCanonicalGuid(value, nameof(value)));
    }

    public bool Equals(ProjectId other)
    {
        return value.Equals(other.value);
    }

    public override bool Equals(object? obj)
    {
        return obj is ProjectId other && Equals(other);
    }

    public override int GetHashCode()
    {
        return value.GetHashCode();
    }

    public override string ToString()
    {
        return Value.ToString("D");
    }

    private static Guid ParseCanonicalGuid(string value, string parameterName)
    {
        if (value == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        Guid parsed;
        if (!Guid.TryParseExact(value, "D", out parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("Value must be a non-empty GUID in D format.", parameterName);
        }

        return parsed;
    }

    private static Guid RequireValue(Guid candidate, string typeName)
    {
        if (candidate == Guid.Empty)
        {
            throw new InvalidOperationException(typeName + " has not been initialized.");
        }

        return candidate;
    }
}

public readonly struct DeviceId : IEquatable<DeviceId>
{
    private readonly Guid value;

    private DeviceId(Guid value)
    {
        this.value = value;
    }

    public Guid Value => RequireValue(value, nameof(DeviceId));

    internal bool IsValid => value != Guid.Empty;

    public static DeviceId New()
    {
        return new DeviceId(Guid.NewGuid());
    }

    public static DeviceId Parse(string value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        Guid parsed;
        if (!Guid.TryParseExact(value, "D", out parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("Value must be a non-empty GUID in D format.", nameof(value));
        }

        return new DeviceId(parsed);
    }

    public bool Equals(DeviceId other)
    {
        return value.Equals(other.value);
    }

    public override bool Equals(object? obj)
    {
        return obj is DeviceId other && Equals(other);
    }

    public override int GetHashCode()
    {
        return value.GetHashCode();
    }

    public override string ToString()
    {
        return Value.ToString("D");
    }

    private static Guid RequireValue(Guid candidate, string typeName)
    {
        if (candidate == Guid.Empty)
        {
            throw new InvalidOperationException(typeName + " has not been initialized.");
        }

        return candidate;
    }
}

public readonly struct CredentialReference : IEquatable<CredentialReference>
{
    private readonly Guid value;

    private CredentialReference(Guid value)
    {
        this.value = value;
    }

    public Guid Value
    {
        get
        {
            if (value == Guid.Empty)
            {
                throw new InvalidOperationException(nameof(CredentialReference) + " has not been initialized.");
            }

            return value;
        }
    }

    internal bool IsValid => value != Guid.Empty;

    public static CredentialReference New()
    {
        return new CredentialReference(Guid.NewGuid());
    }

    public static CredentialReference Parse(string value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        Guid parsed;
        if (!Guid.TryParseExact(value, "D", out parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("Value must be a non-empty opaque GUID in D format.", nameof(value));
        }

        return new CredentialReference(parsed);
    }

    public bool Equals(CredentialReference other)
    {
        return value.Equals(other.value);
    }

    public override bool Equals(object? obj)
    {
        return obj is CredentialReference other && Equals(other);
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

public sealed class ProjectRecord
{
    public ProjectRecord(ProjectId id, string customerName, string projectName, string evidenceRoot, DateTimeOffset createdAt)
    {
        if (!id.IsValid)
        {
            throw new ArgumentException("Project ID must be initialized.", nameof(id));
        }

        Id = id;
        CustomerName = ValidateRequiredText(customerName, nameof(customerName));
        ProjectName = ValidateRequiredText(projectName, nameof(projectName));
        EvidenceRoot = ValidateRequiredText(evidenceRoot, nameof(evidenceRoot));
        CreatedAt = createdAt.ToUniversalTime();
    }

    public ProjectId Id { get; }
    public string CustomerName { get; }
    public string ProjectName { get; }
    public string EvidenceRoot { get; }
    public DateTimeOffset CreatedAt { get; }

    private static string ValidateRequiredText(string value, string parameterName)
    {
        if (value == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be blank.", parameterName);
        }

        return value;
    }
}

public sealed class DeviceRecord
{
    public DeviceRecord(
        DeviceId id,
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        CredentialReference credentialReference,
        DateTimeOffset createdAt)
        : this(
            id,
            projectId,
            displayName,
            host,
            port,
            "未设置",
            TargetCategory.Automatic,
            ConnectionProtocol.Ssh,
            credentialReference,
            createdAt)
    {
    }

    public DeviceRecord(
        DeviceId id,
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        string userName,
        TargetCategory category,
        ConnectionProtocol protocol,
        CredentialReference credentialReference,
        DateTimeOffset createdAt)
    {
        if (!id.IsValid)
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(id));
        }

        if (!projectId.IsValid)
        {
            throw new ArgumentException("Project ID must be initialized.", nameof(projectId));
        }

        if (!credentialReference.IsValid)
        {
            throw new ArgumentException("Credential reference must be initialized.", nameof(credentialReference));
        }

        Id = id;
        ProjectId = projectId;
        DisplayName = ValidateRequiredText(displayName, nameof(displayName));
        Host = ValidateRequiredText(host, nameof(host));
        if (port < 1 || port > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 1 and 65535.");
        }

        Port = port;
        UserName = ValidateRequiredText(userName, nameof(userName));
        if (!Enum.IsDefined(typeof(TargetCategory), category))
        {
            throw new ArgumentOutOfRangeException(nameof(category), category, "Target category is invalid.");
        }

        if (!Enum.IsDefined(typeof(ConnectionProtocol), protocol))
        {
            throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "Connection protocol is invalid.");
        }

        Category = category;
        Protocol = protocol;
        CredentialReference = credentialReference;
        CreatedAt = createdAt.ToUniversalTime();
    }

    public DeviceId Id { get; }
    public ProjectId ProjectId { get; }
    public string DisplayName { get; }
    public string Host { get; }
    public int Port { get; }
    public string UserName { get; }
    public TargetCategory Category { get; }
    public ConnectionProtocol Protocol { get; }
    public CredentialReference CredentialReference { get; }
    public DateTimeOffset CreatedAt { get; }

    private static string ValidateRequiredText(string value, string parameterName)
    {
        if (value == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be blank.", parameterName);
        }

        return value;
    }
}

public sealed class SshHostKeyTrustRecord
{
    public SshHostKeyTrustRecord(DeviceId deviceId, HostKeyTrust trust, long revision)
    {
        if (!deviceId.IsValid)
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        if (revision < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(revision), revision, "Revision cannot be negative.");
        }

        DeviceId = deviceId;
        Trust = trust ?? throw new ArgumentNullException(nameof(trust));
        Revision = revision;
    }

    public DeviceId DeviceId { get; }
    public HostKeyTrust Trust { get; }
    public long Revision { get; }
}

public sealed class PersistenceConcurrencyException : InvalidOperationException
{
    public PersistenceConcurrencyException(string message)
        : base(message)
    {
    }
}

public enum EvidenceFileKind
{
    RawOutput,
    EvidenceImage
}

public sealed class EvidenceFileRecord
{
    public EvidenceFileRecord(
        ProjectId projectId,
        DeviceId deviceId,
        string relativePath,
        string sha256,
        EvidenceFileKind kind,
        int ordinal,
        DateTimeOffset createdAt)
    {
        if (!projectId.IsValid)
        {
            throw new ArgumentException("Project ID must be initialized.", nameof(projectId));
        }

        if (!deviceId.IsValid)
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        ProjectId = projectId;
        DeviceId = deviceId;
        if (!IsValidSha256(sha256))
        {
            throw new ArgumentException("Value must be a SHA-256 hash.", nameof(sha256));
        }

        if (!Enum.IsDefined(typeof(EvidenceFileKind), kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Evidence file kind is invalid.");
        }

        if (ordinal < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ordinal), ordinal, "Ordinal cannot be negative.");
        }

        RelativePath = WindowsEvidenceRelativePathPolicy.Normalize(relativePath, nameof(relativePath));
        Sha256 = sha256;
        Kind = kind;
        Ordinal = ordinal;
        CreatedAt = createdAt.ToUniversalTime();
    }

    public ProjectId ProjectId { get; }
    public DeviceId DeviceId { get; }
    public string RelativePath { get; }
    public string Sha256 { get; }
    public EvidenceFileKind Kind { get; }
    public int Ordinal { get; }
    public DateTimeOffset CreatedAt { get; }

    private static bool IsValidSha256(string? value)
    {
        if (value == null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            var isDecimalDigit = character >= '0' && character <= '9';
            var isLowercaseHexLetter = character >= 'a' && character <= 'f';
            var isUppercaseHexLetter = character >= 'A' && character <= 'F';
            if (!isDecimalDigit && !isLowercaseHexLetter && !isUppercaseHexLetter)
            {
                return false;
            }
        }

        return true;
    }
}
