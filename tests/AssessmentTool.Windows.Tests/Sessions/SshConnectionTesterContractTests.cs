using System;
using System.Linq;
using System.Reflection;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Sessions;
using Xunit;

namespace AssessmentTool.Windows.Tests.Sessions;

public sealed class SshConnectionTesterContractTests
{
    [Fact]
    public void Public_facade_exposes_only_probe_and_zero_command_login_operations()
    {
        Assert.True(typeof(SshConnectionTester).IsPublic);
        var constructor = Assert.Single(typeof(SshConnectionTester).GetConstructors());
        Assert.Equal(typeof(ICredentialVault), Assert.Single(constructor.GetParameters()).ParameterType);

        var methods = typeof(SshConnectionTester).GetMethods(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Select(method => method.Name)
            .OrderBy(name => name)
            .ToArray();

        Assert.Equal(
            new[] { "ProbeHostKeyAsync", "TestLoginWithoutCommandAsync" },
            methods);
        Assert.DoesNotContain(methods, name => name.IndexOf("Execute", StringComparison.OrdinalIgnoreCase) >= 0);
    }
}
