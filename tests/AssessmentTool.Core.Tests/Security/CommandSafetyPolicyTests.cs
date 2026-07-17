using System;
using System.Reflection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Security;
using Xunit;

namespace AssessmentTool.Core.Tests.Security;

public sealed class CommandSafetyPolicyTests
{
    [Theory]
    [InlineData("rm -rf /tmp/x")]
    [InlineData("echo x > /etc/example")]
    [InlineData("id; whoami")]
    [InlineData("uname -a && id")]
    [InlineData("uname -a\nwhoami")]
    [InlineData("echo $(id)")]
    [InlineData("systemctl restart sshd")]
    [InlineData("service nginx stop")]
    [InlineData("configure terminal")]
    [InlineData("delete startup-config")]
    [InlineData("UPDATE users SET enabled = 0")]
    [InlineData("CREATE TABLE evidence (id int)")]
    [InlineData("GRANT SELECT ON users TO auditor")]
    [InlineData("EXECUTE IMMEDIATE 'DROP TABLE evidence'")]
    [InlineData("SELECT pg_write_file('/tmp/x', 'x')")]
    [InlineData("SELECT pg_write_binary_file('/tmp/x', 'x')")]
    [InlineData("SELECT value INTO OUTFILE '/tmp/x' FROM evidence")]
    [InlineData("SELECT value\nINTO OUTFILE '/tmp/x' FROM evidence")]
    [InlineData("docker restart db")]
    [InlineData("podman stop db")]
    [InlineData("New-LocalUser -Name auditor")]
    [InlineData("Set-LocalUser -Name auditor -PasswordNeverExpires $true")]
    [InlineData("Remove-LocalUser -Name auditor")]
    [InlineData("Add-LocalGroupMember -Group Administrators -Member auditor")]
    [InlineData("Remove-LocalGroupMember -Group Administrators -Member auditor")]
    [InlineData("net stop spooler")]
    [InlineData("net start spooler")]
    [InlineData("net user auditor /add")]
    [InlineData("net user auditor NewPassword")]
    [InlineData("useradd auditor")]
    [InlineData("usermod -L auditor")]
    [InlineData("userdel auditor")]
    [InlineData("passwd auditor")]
    [InlineData("docker compose down")]
    [InlineData("docker compose up -d")]
    [InlineData("docker compose restart")]
    [InlineData("docker compose kill")]
    [InlineData("docker compose rm -f")]
    [InlineData("docker compose start")]
    [InlineData("docker compose stop")]
    [InlineData("docker compose pause")]
    [InlineData("docker compose unpause")]
    [InlineData("docker-compose start")]
    [InlineData("docker-compose stop")]
    [InlineData("docker-compose pause")]
    [InlineData("docker-compose unpause")]
    [InlineData("podman compose down")]
    [InlineData("podman compose up -d")]
    [InlineData("podman compose restart")]
    [InlineData("podman compose kill")]
    [InlineData("podman compose rm -f")]
    [InlineData("podman compose start")]
    [InlineData("podman compose stop")]
    [InlineData("podman compose pause")]
    [InlineData("podman compose unpause")]
    [InlineData("podman-compose start")]
    [InlineData("podman-compose stop")]
    [InlineData("podman-compose pause")]
    [InlineData("podman-compose unpause")]
    [InlineData("New-LocalGroup -Name Auditors")]
    [InlineData("Set-LocalGroup -Name Auditors -Description Reviewers")]
    [InlineData("Remove-LocalGroup -Name Auditors")]
    [InlineData("net localgroup Administrators auditor /add")]
    [InlineData("net localgroup Administrators auditor /delete")]
    [InlineData("groupadd auditors")]
    [InlineData("groupmod -n reviewers auditors")]
    [InlineData("groupdel auditors")]
    [InlineData("SELECT lo_export(42, '/tmp/evidence')")]
    [InlineData("SELECT lo_import('/tmp/evidence')")]
    [InlineData("SELECT pg_file_unlink('/tmp/evidence')")]
    [InlineData("SELECT sys_exec('id')")]
    public void Rejects_explicitly_dangerous_commands_with_unsafe_command(string commandText)
    {
        var result = new CommandSafetyPolicy().Validate(VerifiedReadOnlyCommand(commandText));

        Assert.False(result.Allowed);
        Assert.Equal("unsafe-command", result.Code);
    }

    [Fact]
    public void Rejects_command_that_is_not_eligible_for_automatic_execution()
    {
        var command = CreateCommand("uname -a", VerificationStatus.Pending, isReadOnly: true);

        var result = new CommandSafetyPolicy().Validate(command);

        Assert.False(result.Allowed);
        Assert.Equal("unverified-command", result.Code);
    }

    [Fact]
    public void Rejects_command_with_rejected_verification_status()
    {
        var command = CreateCommand("uname -a", VerificationStatus.Rejected, isReadOnly: true);

        var result = new CommandSafetyPolicy().Validate(command);

        Assert.False(result.Allowed);
        Assert.Equal("unverified-command", result.Code);
    }

    [Fact]
    public void Rejects_verified_command_that_is_not_read_only()
    {
        var command = CreateCommand("uname -a", VerificationStatus.Verified, isReadOnly: false);

        var result = new CommandSafetyPolicy().Validate(command);

        Assert.False(result.Allowed);
        Assert.Equal("unverified-command", result.Code);
    }

    [Theory]
    [InlineData("show version")]
    [InlineData("display version")]
    [InlineData("show clock")]
    [InlineData("display clock")]
    [InlineData("uname -a")]
    [InlineData("hostname")]
    [InlineData("cat /etc/os-release")]
    [InlineData("cat /etc/login.defs")]
    [InlineData("ps -ef")]
    [InlineData("systemctl list-units")]
    [InlineData("docker ps")]
    [InlineData("podman ps")]
    [InlineData("Get-ComputerInfo")]
    [InlineData("SELECT current_setting('server_version')")]
    [InlineData("WITH version_info AS (SELECT current_setting('server_version')) SELECT * FROM version_info")]
    [InlineData("  select   current_setting ( 'server_version' )  ")]
    [InlineData("with VERSION_INFO as ( select current_setting('server_version') ) select * from version_info")]
    public void Allows_verified_read_only_command_without_unsafe_syntax(string commandText)
    {
        var result = new CommandSafetyPolicy().Validate(VerifiedReadOnlyCommand(commandText));

        Assert.True(result.Allowed);
        Assert.Equal("allowed", result.Code);
    }

    [Theory]
    [InlineData("ps -eo pid,comm")]
    [InlineData("systemctl list-units --type=service --state=running --no-pager")]
    [InlineData("docker ps --no-trunc --format '{\"Image\":{{json .Image}},\"Names\":{{json .Names}},\"Ports\":{{json .Ports}}}'")]
    [InlineData("podman ps --no-trunc --format '{\"Image\":{{json .Image}},\"Names\":{{json .Names}},\"Ports\":{{json .Ports}}}'")]
    public void Allows_exact_inventory_command_templates(string commandText)
    {
        var result = new CommandSafetyPolicy().Validate(VerifiedReadOnlyCommand(commandText));

        Assert.True(result.Allowed);
        Assert.Equal("allowed", result.Code);
    }

    [Theory]
    [InlineData("docker exec db ps", "unsafe-command")]
    [InlineData("podman exec db ps", "unsafe-command")]
    [InlineData("systemctl restart sshd", "unsafe-command")]
    [InlineData("docker start db", "unsafe-command")]
    [InlineData("podman restart db", "unsafe-command")]
    [InlineData("docker ps --no-trunc --format {{.ID}}", "unsupported-command-shape")]
    [InlineData("podman ps --no-trunc --format {{.Names}}", "unsupported-command-shape")]
    [InlineData("docker ps --no-trunc --format {{json .}}", "unsupported-command-shape")]
    [InlineData("podman ps --no-trunc --format {{json .}}", "unsupported-command-shape")]
    [InlineData("ps -eo pid,comm,args", "unsupported-command-shape")]
    [InlineData("ps -eo pid,comm,args --sort=pid", "unsupported-command-shape")]
    [InlineData("systemctl list-units --type=service --state=running --no-pager --all", "unsupported-command-shape")]
    [InlineData("docker ps --no-trunc --format {{json .}} --all", "unsupported-command-shape")]
    [InlineData("podman ps --no-trunc --format {{json .}} --quiet", "unsupported-command-shape")]
    [InlineData("ps -eo pid,comm,args | cat", "unsafe-command")]
    [InlineData("systemctl list-units --type=service --state=running --no-pager > services.txt", "unsafe-command")]
    [InlineData("docker ps --no-trunc --format {{json .}} | cat", "unsafe-command")]
    [InlineData("podman ps --no-trunc --format {{json .}} >> containers.txt", "unsafe-command")]
    public void Rejects_dangerous_variants_of_inventory_command_templates(string commandText, string expectedCode)
    {
        var result = new CommandSafetyPolicy().Validate(VerifiedReadOnlyCommand(commandText));

        Assert.False(result.Allowed);
        Assert.Equal(expectedCode, result.Code);
    }

    [Theory]
    [InlineData("echo harmless")]
    [InlineData("ls -la")]
    [InlineData("Get-X")]
    [InlineData("Get-CustomInventory")]
    [InlineData("Get-ComputerInfo -Property OsName")]
    [InlineData("Get-ComputerInfo OsName")]
    [InlineData("show clock version")]
    [InlineData("show clock detail")]
    [InlineData("display clock version")]
    [InlineData("display clock detail")]
    [InlineData("SELECT version()")]
    [InlineData("SELECT * FROM pg_settings")]
    [InlineData("SELECT current_setting('server_version', true)")]
    [InlineData("SELECT current_setting($1)")]
    [InlineData("SELECT current_setting('server_version') -- audit")]
    [InlineData("SELECT current_setting('server_version') /* audit */")]
    [InlineData("WITH version_info AS (SELECT current_setting('server_version')) SELECT version_info FROM version_info")]
    public void Rejects_verified_read_only_command_with_an_unsupported_shape(string commandText)
    {
        var result = new CommandSafetyPolicy().Validate(VerifiedReadOnlyCommand(commandText));

        Assert.False(result.Allowed);
        Assert.Equal("unsupported-command-shape", result.Code);
    }

    [Theory]
    [InlineData("uname -a && id")]
    [InlineData("SELECT pg_write_file('/tmp/x', 'x')")]
    [InlineData("SELECT current_setting('server_version') > /tmp/evidence")]
    [InlineData("SELECT current_setting('server_version'); SELECT version()")]
    [InlineData("SELECT setval('audit_sequence', 1)")]
    [InlineData("SELECT nextval('audit_sequence')")]
    [InlineData("SELECT pg_advisory_lock(1)")]
    [InlineData("SELECT pg_try_advisory_lock(1)")]
    [InlineData("SELECT GET_LOCK('audit', 1)")]
    [InlineData("SELECT RELEASE_LOCK('audit')")]
    [InlineData("SELECT * FROM evidence FOR UPDATE")]
    [InlineData("SELECT * FROM evidence FOR SHARE")]
    [InlineData("SELECT * FROM evidence FOR KEY SHARE")]
    [InlineData("SELECT * FROM evidence LOCK IN SHARE MODE")]
    [InlineData("docker compose --project-name audit stop")]
    [InlineData("docker compose -f stack.yml pause")]
    [InlineData("podman-compose -f stack.yml pause")]
    [InlineData("net.exe localgroup Administrators auditor /add")]
    [InlineData("net.exe stop Spooler")]
    public void Rejects_forbidden_syntax_inside_a_recognized_read_only_shape(string commandText)
    {
        var result = new CommandSafetyPolicy().Validate(VerifiedReadOnlyCommand(commandText));

        Assert.False(result.Allowed);
        Assert.Equal("unsafe-command", result.Code);
    }

    [Fact]
    public void Safety_decision_cannot_be_mutated_or_publicly_constructed_as_allowed()
    {
        var result = new CommandSafetyPolicy().Validate(VerifiedReadOnlyCommand("show version"));

        Assert.All(typeof(SafetyDecision).GetProperties(BindingFlags.Instance | BindingFlags.Public),
            property => Assert.Null(property.SetMethod));
        Assert.Empty(typeof(SafetyDecision).GetConstructors());
        Assert.True(result.Allowed);
    }

    [Fact]
    public void Command_definition_cannot_be_publicly_constructed_or_mutated()
    {
        Assert.Empty(typeof(CommandDefinition).GetConstructors());
        Assert.All(typeof(CommandDefinition).GetProperties(BindingFlags.Instance | BindingFlags.Public),
            property => Assert.Null(property.SetMethod));
    }

    private static CommandDefinition VerifiedReadOnlyCommand(string commandText)
    {
        return CreateCommand(commandText, VerificationStatus.Verified, isReadOnly: true);
    }

    private static CommandDefinition CreateCommand(
        string commandText,
        VerificationStatus verificationStatus,
        bool isReadOnly)
    {
        return new CommandDefinition(
            "cmd-1",
            "查询版本",
            TargetCategory.NetworkDevice,
            commandText,
            verificationStatus,
            isReadOnly,
            "Vendor",
            "Product",
            "1.0",
            "2.0",
            "AC-1",
            "Model range",
            "只读审计账户",
            CommandRiskLevel.Low,
            TimeSpan.FromSeconds(30),
            PagingBehavior.DisablePaging,
            "确认系统版本",
            new DateTime(2025, 2, 3),
            "https://example.com/commands/show-version");
    }
}
