namespace AssessmentTool.Core.Detection;

public static class BuiltInIdentificationRules
{
    private static readonly IdentificationRule LinuxOsReleaseIdRule =
        IdentificationRule.CreateVerified(
            Domain.TargetCategory.Server,
            "^ID=\\\"?(?<vendor>[a-z0-9._-]+)\\\"?$",
            0.95,
            "https://www.freedesktop.org/software/systemd/man/latest/os-release.html");

    private static readonly IdentificationRule HuaweiVrpRule =
        IdentificationRule.CreateVerified(
            Domain.TargetCategory.NetworkDevice,
            "^(?<vendor>Huawei) Versatile Routing Platform Software$",
            0.85,
            "https://info.support.huawei.com/enterprise/en/doc/EDOC1100352648/91652f17/device-status-checking-commands");

    private static readonly IdentificationRule H3cComwareRule =
        IdentificationRule.CreateVerified(
            Domain.TargetCategory.NetworkDevice,
            "^(?<vendor>H3C) (?<productFamily>Comware)(?: Platform)? Software, Version (?<version>(?:7|9)\\.[0-9.]+)(?:, .+)?$",
            0.85,
            "https://www.h3c.com/cn/d_202503/2368787_30005_0.htm");

    private static readonly IdentificationRule WindowsServerRule =
        IdentificationRule.CreateVerifiedWithFixedIdentity(
            Domain.TargetCategory.Server,
            "^\\s*ProductName\\s+REG_SZ\\s+Windows Server (?<version>2016|2019|2022|2025)(?: (?<model>.+?))?\\s*$",
            0.89,
            "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query",
            "Microsoft",
            "Windows Server");

    public static IdentificationRule LinuxOsReleaseId => LinuxOsReleaseIdRule;

    public static IdentificationRule HuaweiVrp => HuaweiVrpRule;

    public static IdentificationRule H3cComware => H3cComwareRule;

    public static IdentificationRule WindowsServer => WindowsServerRule;
}
