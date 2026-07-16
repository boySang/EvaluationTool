using System.Threading.Tasks;
using AssessmentTool.Windows.Components;

namespace AssessmentTool.App.Services;

public interface IComponentStatusService
{
    Task<ComponentStatus> GetPlinkStatusAsync();
}
