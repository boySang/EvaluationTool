using System;

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

public sealed class ConnectionProfile
{
    public ConnectionProfile(string displayName, string host, int port, ConnectionProtocol protocol)
    {
        DisplayName = ValidateRequiredText(displayName, nameof(displayName));
        Host = ValidateRequiredText(host, nameof(host));
        if (port < 1 || port > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 1 and 65535.");
        }

        Port = port;
        Protocol = protocol;
        TargetCategory = TargetCategory.Automatic;
    }

    public string DisplayName { get; }
    public string Host { get; }
    public int Port { get; }
    public ConnectionProtocol Protocol { get; }
    public TargetCategory TargetCategory { get; set; }
    public string? PinnedHostKey { get; set; }

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
