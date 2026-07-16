using System;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Execution;

namespace AssessmentTool.App.Services;

internal sealed class UnavailableCollectionWorkflowService : ICollectionWorkflowService
{
    public Task<CollectionWorkflowResult> RunAsync(
        CollectionWorkflowRequest request,
        IProgress<CollectionProgress> progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(CollectionWorkflowResult.Failed(new CollectionError(
            "采集服务尚未完成现场配置",
            "当前没有已选择且通过组件与主机指纹检查的设备",
            "请先创建项目、添加设备，并在组件中心完成 Plink 检查",
            "CollectionWorkflowUnavailable")));
    }
}
