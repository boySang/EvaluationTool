using System;
using System.Linq;
using System.Reflection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Sessions;
using Xunit;

namespace AssessmentTool.Windows.Tests.Sessions;

public sealed class SshReadOnlySessionFactoryContractTests
{
    [Fact]
    public void Public_factory_accepts_only_vault_and_confirmed_profile()
    {
        var constructor = Assert.Single(typeof(SshReadOnlySessionFactory).GetConstructors());
        Assert.Equal(typeof(ICredentialVault), Assert.Single(constructor.GetParameters()).ParameterType);
        var create = Assert.Single(typeof(SshReadOnlySessionFactory).GetMethods(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly));
        Assert.Equal("Create", create.Name);
        Assert.Equal(typeof(ConnectionProfile), Assert.Single(create.GetParameters()).ParameterType);
        Assert.Equal(typeof(IRemoteSession), create.ReturnType);
    }
}
