#pragma once

namespace AssessmentTool::Bootstrapper
{
    enum class BootstrapAction
    {
        ShowUnsupportedWindows,
        ShowDotNetRemediation,
        ShowRepairFiles,
        LaunchApplication
    };

    struct BootstrapDecisionInput
    {
        bool IsSupportedWindows;
        bool HasDotNet48;
        bool HasApplicationExecutable;
        bool HasIntegrityManifest;
        bool IsApplicationHashValid;
    };

    BootstrapAction DecideBootstrapAction(const BootstrapDecisionInput& input) noexcept;
}
