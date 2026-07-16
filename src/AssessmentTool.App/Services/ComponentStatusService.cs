using System.Threading.Tasks;
using AssessmentTool.Windows.Components;

namespace AssessmentTool.App.Services;

public sealed class ComponentStatusService : IComponentStatusService
{
    public Task<ComponentStatus> GetPlinkStatusAsync()
    {
        return Task.Run(() =>
            new ComponentInspector().Inspect(TrustedComponentCatalog.Plink));
    }
}
