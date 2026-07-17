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
        viewModel.PortText = "70000";

        Assert.False(viewModel.CanContinue);
        Assert.Throws<InvalidOperationException>(() => viewModel.Next());

        viewModel.PortText = "22";
        viewModel.Next();
        viewModel.Back();

        Assert.Equal(DeviceEditorStep.ConnectionConfiguration, viewModel.Step);
        Assert.Equal("reader", viewModel.UserName);
    }
}
