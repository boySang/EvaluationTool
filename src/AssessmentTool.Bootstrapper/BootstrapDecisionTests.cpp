#include "BootstrapDecision.h"

#include <iostream>

using AssessmentTool::Bootstrapper::BootstrapAction;
using AssessmentTool::Bootstrapper::BootstrapDecisionInput;
using AssessmentTool::Bootstrapper::DecideBootstrapAction;

namespace
{
    int failures = 0;

    void Expect(const char* name, BootstrapAction expected, const BootstrapDecisionInput& input)
    {
        if (DecideBootstrapAction(input) != expected)
        {
            std::cerr << "FAILED: " << name << std::endl;
            ++failures;
        }
    }
}

int main()
{
    const BootstrapDecisionInput ready{ true, true, true, true, true };
    Expect(
        "unsupported Windows takes precedence",
        BootstrapAction::ShowUnsupportedWindows,
        { false, false, false, false, false });
    Expect(
        "missing .NET is remediated before package inspection",
        BootstrapAction::ShowDotNetRemediation,
        { true, false, false, false, false });
    Expect(
        "missing application requests package repair",
        BootstrapAction::ShowRepairFiles,
        { true, true, false, true, false });
    Expect(
        "missing manifest requests package repair",
        BootstrapAction::ShowRepairFiles,
        { true, true, true, false, true });
    Expect(
        "hash mismatch requests package repair",
        BootstrapAction::ShowRepairFiles,
        { true, true, true, true, false });
    Expect(
        "complete trusted package launches",
        BootstrapAction::LaunchApplication,
        ready);

    if (failures != 0)
    {
        std::cerr << failures << " bootstrap decision test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "All bootstrap decision tests passed." << std::endl;
    return 0;
}
