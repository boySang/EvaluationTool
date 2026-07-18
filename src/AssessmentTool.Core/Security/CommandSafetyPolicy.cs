using System;
using System.Text.RegularExpressions;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Core.Security;

public sealed class CommandSafetyPolicy
{
    private const string DockerInventoryCommand = "docker ps --no-trunc --format '{\"Image\":{{json .Image}},\"Names\":{{json .Names}},\"Ports\":{{json .Ports}}}'";
    private const string PodmanInventoryCommand = "podman ps --no-trunc --format '{\"Image\":{{json .Image}},\"Names\":{{json .Names}},\"Ports\":{{json .Ports}}}'";
    private const string HuaweiDisplayVersionCommand = "display version | no-more";
    private const string HuaweiDisplayAaaConfigurationCommand = "display aaa configuration | no-more";
    private const string H3cDisplayPasswordControlCommand = "display password-control | no-more";
    private const string WindowsServerProductNameCommand =
        "cmd.exe /d /c %SystemRoot%\\System32\\reg.exe query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductName";
    private const string WindowsServerBuildNumberCommand =
        "cmd.exe /d /c %SystemRoot%\\System32\\reg.exe query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v CurrentBuildNumber";
    private const string WindowsServerAccountPolicyCommand =
        "cmd.exe /d /c %SystemRoot%\\System32\\net.exe accounts";
    private const string NginxVersionCommand = "/usr/sbin/nginx -v";
    private const string NginxBuildOptionsCommand = "/usr/sbin/nginx -V";
    private const string ApacheHttpdVersionCommand = "/usr/sbin/httpd -v";
    private const string ApacheHttpdBuildOptionsCommand = "/usr/sbin/httpd -V";

    private static readonly Regex RecognizedReadOnlyRoot = new Regex(
        @"^(?:(?:show|display)\b|uname\b|hostname\b|cat\b|ps\b|systemctl\s+list-units\b|(?:docker|podman)\s+ps\b|Get-ComputerInfo$|(?:select|with)\b)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex AllowedReadOnlyShape = new Regex(
        @"^(?:(?:show|display)\s+(?!clock(?:\s|$))(?:(?:[A-Za-z0-9_-]+\s+){0,3})version(?:\s+[A-Za-z0-9_.-]+)*|(?:show|display)\s+clock|uname(?:\s+-[A-Za-z]+)?|hostname|cat\s+(?:/etc/os-release|/etc/lsb-release|/etc/redhat-release|/etc/debian_version|/etc/login\.defs|/proc/version|/proc/cpuinfo|/proc/meminfo)|ps\s+-eo\s+pid,comm|systemctl\s+list-units|systemctl\s+list-units\s+--type=service\s+--state=running\s+--no-pager|(?:docker|podman)\s+ps(?:\s+(?:-a|--all|--no-trunc|--quiet|--size))*|Get-ComputerInfo)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex AllowedSqlMetadataTemplate = new Regex(
        @"^(?:SELECT[ \t]+current_setting[ \t]*\([ \t]*'server_version'[ \t]*\)|WITH[ \t]+version_info[ \t]+AS[ \t]*\([ \t]*SELECT[ \t]+current_setting[ \t]*\([ \t]*'server_version'[ \t]*\)[ \t]*\)[ \t]+SELECT[ \t]+\*[ \t]+FROM[ \t]+version_info)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex ForbiddenSyntax = new Regex(
        @"(?:[\r\n]|;|&&|\|\||(?<!\|)\|(?!\|)|(?<![<>=])>{1,2}(?![=>])|(?<![<>=])<(?![=>])|`|\$\(|\b(?:rm|mv|cp|dd|tee|touch|chmod|chown)\b|\bsed\s+-[A-Za-z]*i\b|\bsystemctl\s+(?:start|stop|restart|reload|enable|disable)\s+\S+\b|\bservice\s+\S+\s+(?:start|stop|restart|reload|enable|disable)\b|\bsc\s+(?:start|stop|config|delete)\b|\b(?:start|stop|restart|set)-service\b|\b(?:new|set|remove)-localuser\b|\b(?:new|set|remove)-localgroup\b|\b(?:add|remove)-localgroupmember\b|\bnet(?:\.exe)?\s+(?:start|stop)\b|\bnet(?:\.exe)?\s+localgroup\b[^\r\n]*/(?:add|delete)\b|\bnet(?:\.exe)?\s+user\s+\S+\s+(?!/domain\b)\S+|\b(?:useradd|usermod|userdel|passwd|groupadd|groupmod|groupdel)\b|\b(?:configure|config)\b|\b(?:delete|erase)\b|\bwrite\s+(?:memory|terminal)\b|\b(?:reload|shutdown|reboot)\b|\b(?:docker|podman)(?:-compose|\s+compose)?(?:\s+\S+)*\s+(?:down|up|run|start|stop|restart|rm|kill|pause|unpause|exec)\b|\b(?:insert|update|delete|merge|replace|create|alter|drop|truncate|grant|revoke|execute|exec|call|do)\b|\bcopy\b.*\bto\b|\bselect\b.*\binto\b|\bfor\s+(?:update|share|key\s+share)\b|\block\s+in\s+share\s+mode\b|\b(?:updlock|xlock|holdlock)\b|\b(?:setval|nextval|pg_advisory_lock|pg_try_advisory_lock|get_lock|release_lock|pg_write_file|pg_write_binary_file|pg_file_unlink|pg_file_rename|pg_read_file|pg_read_binary_file|lo_export|lo_import|xp_cmdshell|dblink_exec|sys_exec|sys_eval|sp_oacreate|sp_oamethod|load_file)\s*\()",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public SafetyDecision Validate(CommandDefinition command)
    {
        if (command == null)
        {
            throw new ArgumentNullException(nameof(command));
        }

        if (!command.IsEligibleForAutomaticExecution)
        {
            return SafetyDecision.Reject("unverified-command", "命令未通过已验证只读命令包的自动执行资格检查。");
        }

        var commandText = command.CommandText?.Trim();
        if (ForbiddenSyntax.IsMatch(commandText)
            && !IsAllowedNetworkNoMore(commandText)
            && !IsAllowedWindowsServerCommand(commandText)
            && !IsAllowedNginxCommand(commandText)
            && !IsAllowedApacheHttpdCommand(commandText))
        {
            return SafetyDecision.Reject("unsafe-command", "命令包含可能修改目标或组合执行的语法。");
        }

        var isAllowedWindowsServerCommand = IsAllowedWindowsServerCommand(commandText);
        var isAllowedNginxCommand = IsAllowedNginxCommand(commandText);
        var isAllowedApacheHttpdCommand = IsAllowedApacheHttpdCommand(commandText);
        if (string.IsNullOrEmpty(commandText)
            || (!isAllowedWindowsServerCommand && !isAllowedNginxCommand && !isAllowedApacheHttpdCommand
                && (!RecognizedReadOnlyRoot.IsMatch(commandText)
                    || (!AllowedReadOnlyShape.IsMatch(commandText)
                && !AllowedSqlMetadataTemplate.IsMatch(commandText)
                && !IsAllowedContainerInventory(commandText)
                && !IsAllowedNetworkNoMore(commandText)))))
        {
            return SafetyDecision.Reject("unsupported-command-shape", "命令不属于允许自动执行的只读命令形状。");
        }

        return SafetyDecision.Allow();
    }

    private static bool IsAllowedContainerInventory(string? commandText)
    {
        return string.Equals(commandText, DockerInventoryCommand, StringComparison.Ordinal)
            || string.Equals(commandText, PodmanInventoryCommand, StringComparison.Ordinal);
    }

    private static bool IsAllowedNetworkNoMore(string? commandText)
    {
        return string.Equals(commandText, HuaweiDisplayVersionCommand, StringComparison.Ordinal)
            || string.Equals(commandText, HuaweiDisplayAaaConfigurationCommand, StringComparison.Ordinal)
            || string.Equals(commandText, H3cDisplayPasswordControlCommand, StringComparison.Ordinal);
    }

    private static bool IsAllowedWindowsServerCommand(string? commandText)
    {
        return string.Equals(commandText, WindowsServerProductNameCommand, StringComparison.Ordinal)
            || string.Equals(commandText, WindowsServerBuildNumberCommand, StringComparison.Ordinal)
            || string.Equals(commandText, WindowsServerAccountPolicyCommand, StringComparison.Ordinal);
    }

    private static bool IsAllowedNginxCommand(string? commandText)
    {
        return string.Equals(commandText, NginxVersionCommand, StringComparison.Ordinal)
            || string.Equals(commandText, NginxBuildOptionsCommand, StringComparison.Ordinal);
    }

    private static bool IsAllowedApacheHttpdCommand(string? commandText)
    {
        return string.Equals(commandText, ApacheHttpdVersionCommand, StringComparison.Ordinal)
            || string.Equals(commandText, ApacheHttpdBuildOptionsCommand, StringComparison.Ordinal);
    }
}

public sealed class SafetyDecision
{
    private SafetyDecision(bool allowed, string code, string message)
    {
        Allowed = allowed;
        Code = code;
        Message = message;
    }

    public bool Allowed { get; }
    public string Code { get; }
    public string Message { get; }

    internal static SafetyDecision Allow()
    {
        return new SafetyDecision(true, "allowed", "命令符合自动执行的只读安全策略。");
    }

    internal static SafetyDecision Reject(string code, string message)
    {
        return new SafetyDecision(false, code, message);
    }
}
