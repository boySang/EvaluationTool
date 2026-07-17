using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Core.Execution;

public interface ICollectionExecutionObserver
{
    Task OnPlanReadyAsync(
        DetectionResult detection,
        IReadOnlyList<CommandDefinition> commands,
        CancellationToken cancellationToken);

    Task OnCommandCompletedAsync(
        CommandDefinition command,
        CommandOutput output,
        CancellationToken cancellationToken);
}
