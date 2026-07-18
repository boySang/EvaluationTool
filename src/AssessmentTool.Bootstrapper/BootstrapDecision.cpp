#include "BootstrapDecision.h"

namespace AssessmentTool::Bootstrapper
{
    BootstrapAction DecideBootstrapAction(const BootstrapDecisionInput& input) noexcept
    {
        if (!input.IsSupportedWindows)
        {
            return BootstrapAction::ShowUnsupportedWindows;
        }

        if (!input.HasDotNet48)
        {
            return BootstrapAction::ShowDotNetRemediation;
        }

        if (!input.HasApplicationExecutable
            || !input.HasIntegrityManifest
            || !input.IsApplicationHashValid)
        {
            return BootstrapAction::ShowRepairFiles;
        }

        return BootstrapAction::LaunchApplication;
    }
}
