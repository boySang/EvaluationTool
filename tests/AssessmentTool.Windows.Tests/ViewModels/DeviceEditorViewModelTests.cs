using System;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class DeviceEditorViewModelTests
{
    [Fact]
    public void Wizard_requires_each_steps_fields_before_advancing()
    {
        var viewModel = new DeviceEditorViewModel();

        viewModel.Start();
        Assert.True(viewModel.IsOpen);
        Assert.Equal(DeviceEditorStep.BasicInformation, viewModel.Step);
        Assert.False(viewModel.CanContinue);

        viewModel.DisplayName = "核心交换机";
        viewModel.Host = "192.0.2.10";
        viewModel.Category = TargetCategory.NetworkDevice;
        Assert.True(viewModel.CanContinue);

        viewModel.Next();
        Assert.Equal(DeviceEditorStep.ConnectionConfiguration, viewModel.Step);
        Assert.False(viewModel.CanContinue);

        viewModel.UserName = "audit-reader";
        viewModel.SetPasswordAvailability(true);
        Assert.True(viewModel.CanContinue);
        viewModel.Next();

        Assert.Equal(DeviceEditorStep.SaveAndTest, viewModel.Step);
        Assert.Equal(ConnectionProtocol.Ssh, viewModel.Protocol);
        Assert.True(viewModel.CanContinue);
    }

    [Fact]
    public void Wizard_rejects_invalid_port_and_can_move_back_without_losing_fields()
    {
        var viewModel = new DeviceEditorViewModel();
        viewModel.Start();
        viewModel.DisplayName = "服务器";
        viewModel.Host = "server.example";
        viewModel.Next();
        viewModel.UserName = "reader";
        viewModel.SetPasswordAvailability(true);
        viewModel.PortText = "70000";

        Assert.False(viewModel.CanContinue);
        Assert.Throws<InvalidOperationException>(() => viewModel.Next());

        viewModel.PortText = "22";
        viewModel.Next();
        viewModel.Back();

        Assert.Equal(DeviceEditorStep.ConnectionConfiguration, viewModel.Step);
        Assert.Equal("reader", viewModel.UserName);
    }

    [Fact]
    public void Private_key_authentication_requires_material_and_only_exposes_safe_file_name()
    {
        var viewModel = CreateConnectionStepViewModel();
        viewModel.AuthenticationMethod = SshAuthenticationMethod.PrivateKey;

        Assert.False(viewModel.CanContinue);
        Assert.Empty(viewModel.PrivateKeyFileName);

        var material = "private-key-material".ToCharArray();
        viewModel.SetPrivateKeyMaterial(material, "audit-reader.ppk");

        Assert.True(viewModel.CanContinue);
        Assert.True(viewModel.HasPrivateKeyMaterial);
        Assert.Equal("audit-reader.ppk", viewModel.PrivateKeyFileName);
        Assert.DoesNotContain(@"C:\", viewModel.PrivateKeyFileName);
    }

    [Fact]
    public void Switching_authentication_clears_private_key_material()
    {
        var viewModel = CreateConnectionStepViewModel();
        viewModel.AuthenticationMethod = SshAuthenticationMethod.PrivateKey;
        var material = "private-key-material".ToCharArray();
        viewModel.SetPrivateKeyMaterial(material, "reader.ppk");

        viewModel.AuthenticationMethod = SshAuthenticationMethod.Password;

        Assert.All(material, character => Assert.Equal('\0', character));
        Assert.False(viewModel.HasPrivateKeyMaterial);
        Assert.Empty(viewModel.PrivateKeyFileName);
    }

    [Fact]
    public void Canceling_editor_clears_private_key_material()
    {
        var viewModel = CreateConnectionStepViewModel();
        viewModel.AuthenticationMethod = SshAuthenticationMethod.PrivateKey;
        var material = "private-key-material".ToCharArray();
        viewModel.SetPrivateKeyMaterial(material, "reader.ppk");

        viewModel.Close();

        Assert.All(material, character => Assert.Equal('\0', character));
        Assert.False(viewModel.IsOpen);
        Assert.False(viewModel.HasPrivateKeyMaterial);
    }

    [Fact]
    public void Taking_private_key_removes_it_from_view_model_until_caller_clears_it()
    {
        var viewModel = CreateConnectionStepViewModel();
        viewModel.AuthenticationMethod = SshAuthenticationMethod.PrivateKey;
        var material = "private-key-material".ToCharArray();
        viewModel.SetPrivateKeyMaterial(material, "reader.ppk");

        var taken = viewModel.TakePrivateKeyMaterial();

        Assert.Same(material, taken);
        Assert.False(viewModel.HasPrivateKeyMaterial);
        Assert.Empty(viewModel.PrivateKeyFileName);
        Array.Clear(taken, 0, taken.Length);
    }

    private static DeviceEditorViewModel CreateConnectionStepViewModel()
    {
        var viewModel = new DeviceEditorViewModel();
        viewModel.Start();
        viewModel.DisplayName = "服务器";
        viewModel.Host = "server.example";
        viewModel.Next();
        viewModel.UserName = "reader";
        return viewModel;
    }
}
