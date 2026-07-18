using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Detection;

public sealed class BuiltInIdentificationRulesTests
{
    [Fact]
    public void Huawei_vrp_banner_creates_low_confidence_network_candidate_for_human_confirmation()
    {
        var result = new DetectionEngine().Detect(
            "Huawei Versatile Routing Platform Software\nVRP (R) software, Version 8.200",
            new[] { BuiltInIdentificationRules.HuaweiVrp });

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(TargetCategory.NetworkDevice, candidate.Category);
        Assert.Equal("Huawei", candidate.Vendor);
        Assert.Equal(0.85, candidate.Confidence);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("H3C Comware Software, Version 7.1.070, Ess 6505", "7.1.070")]
    [InlineData("H3C Comware Software, Version 9.1.055, Demo 5202P14", "9.1.055")]
    public void H3c_comware_banner_creates_versioned_candidate_for_human_confirmation(
        string banner,
        string expectedVersion)
    {
        var result = new DetectionEngine().Detect(
            banner,
            new[] { BuiltInIdentificationRules.H3cComware });

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(TargetCategory.NetworkDevice, candidate.Category);
        Assert.Equal("H3C", candidate.Vendor);
        Assert.Equal("Comware", candidate.ProductFamily);
        Assert.Equal(expectedVersion, candidate.Version);
        Assert.Equal(0.85, candidate.Confidence);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Fact]
    public void H3c_comware_5_is_not_misrepresented_as_verified_adapter_scope()
    {
        var result = new DetectionEngine().Detect(
            "H3C Comware Platform Software, Version 5.20, 0000",
            new[] { BuiltInIdentificationRules.H3cComware });

        Assert.Empty(result.Candidates);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("ProductName    REG_SZ    Windows Server 2016 Standard", "2016", "Standard")]
    [InlineData("ProductName    REG_SZ    Windows Server 2019 Datacenter", "2019", "Datacenter")]
    [InlineData("ProductName    REG_SZ    Windows Server 2022 Standard Evaluation", "2022", "Standard Evaluation")]
    [InlineData("ProductName    REG_SZ    Windows Server 2025 Datacenter", "2025", "Datacenter")]
    public void Windows_server_registry_product_name_creates_verified_fixed_identity_candidate(
        string output,
        string expectedVersion,
        string expectedModel)
    {
        var result = new DetectionEngine().Detect(
            output,
            new[] { BuiltInIdentificationRules.WindowsServer });

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(TargetCategory.Server, candidate.Category);
        Assert.Equal("Microsoft", candidate.Vendor);
        Assert.Equal("Windows Server", candidate.ProductFamily);
        Assert.Equal(expectedVersion, candidate.Version);
        Assert.Equal(expectedModel, candidate.Model);
        Assert.Equal(0.89, candidate.Confidence);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("ProductName    REG_SZ    Windows 11 Enterprise")]
    [InlineData("ProductName    REG_SZ    Windows Server 2012 R2 Standard")]
    [InlineData("ProductName    REG_SZ    Windows Server Preview")]
    public void Windows_server_rule_rejects_clients_and_unverified_versions(string output)
    {
        var result = new DetectionEngine().Detect(
            output,
            new[] { BuiltInIdentificationRules.WindowsServer });

        Assert.Empty(result.Candidates);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("nginx version: nginx/1.24.0", "1.24.0")]
    [InlineData("nginx version: nginx/1.29.8", "1.29.8")]
    public void Nginx_version_output_creates_middleware_candidate_for_human_confirmation(
        string output,
        string expectedVersion)
    {
        var result = new DetectionEngine().Detect(
            output,
            new[] { BuiltInIdentificationRules.NginxLinux });

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(TargetCategory.Middleware, candidate.Category);
        Assert.Equal("NGINX", candidate.Vendor);
        Assert.Equal("Nginx", candidate.ProductFamily);
        Assert.Equal(expectedVersion, candidate.Version);
        Assert.Equal(0.85, candidate.Confidence);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("nginx version: openresty/1.21.4.1")]
    [InlineData("nginx version: nginx/unknown")]
    [InlineData("Apache/2.4.62")]
    public void Nginx_rule_rejects_other_products_and_unusable_versions(string output)
    {
        var result = new DetectionEngine().Detect(
            output,
            new[] { BuiltInIdentificationRules.NginxLinux });

        Assert.Empty(result.Candidates);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("Server version: Apache/2.4.62 (Unix)", "2.4.62")]
    [InlineData("Server version: Apache/2.4.57", "2.4.57")]
    public void Apache_httpd_rule_returns_fixed_verified_identity(string output, string expectedVersion)
    {
        var result = new DetectionEngine().Detect(
            output,
            new[] { BuiltInIdentificationRules.ApacheHttpdLinux });

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(TargetCategory.Middleware, candidate.Category);
        Assert.Equal("Apache Software Foundation", candidate.Vendor);
        Assert.Equal("Apache HTTP Server", candidate.ProductFamily);
        Assert.Equal(expectedVersion, candidate.Version);
        Assert.Equal(0.85, candidate.Confidence);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("Server version: nginx/1.24.0")]
    [InlineData("Apache/2.4.62 (Unix)")]
    [InlineData("Server version: Apache Tomcat/9.0.80")]
    [InlineData("Server version: Apache/2.2.34 (Unix)")]
    [InlineData("Server version: Apache/3.0.0 (Unix)")]
    public void Apache_httpd_rule_rejects_other_or_ambiguous_products(string output)
    {
        var result = new DetectionEngine().Detect(
            output,
            new[] { BuiltInIdentificationRules.ApacheHttpdLinux });

        Assert.Empty(result.Candidates);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("ID=ubuntu", "ubuntu")]
    [InlineData("ID=\"kylin\"", "kylin")]
    [InlineData("ID=uos", "uos")]
    public void Linux_os_release_rule_identifies_vendor_without_guessing_version(
        string line,
        string expectedVendor)
    {
        var result = new DetectionEngine().Detect(
            line,
            new[] { BuiltInIdentificationRules.LinuxOsReleaseId });

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(TargetCategory.Server, candidate.Category);
        Assert.Equal(expectedVendor, candidate.Vendor);
        Assert.Null(candidate.Version);
        Assert.Equal(0.95, candidate.Confidence);
    }

    [Theory]
    [InlineData("ID=ubuntu\nVERSION_ID=24.04", "ubuntu", "24.04")]
    [InlineData("ID=\"kylin\"\r\nVERSION_ID=\"10.1\"", "kylin", "10.1")]
    public void Linux_os_release_enricher_uses_explicit_version_id(
        string transcript,
        string expectedVendor,
        string expectedVersion)
    {
        var detected = new DetectionEngine().Detect(
            transcript,
            new[] { BuiltInIdentificationRules.LinuxOsReleaseId });

        var result = new LinuxOsReleaseVersionEnricher().Enrich(transcript, detected);

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(expectedVendor, candidate.Vendor);
        Assert.Equal(expectedVersion, candidate.Version);
        Assert.Contains("VERSION_ID=" + expectedVersion, candidate.Evidence);
    }

    [Theory]
    [InlineData("ID=ubuntu\nVERSION_ID=24.04\nVERSION_ID=22.04")]
    [InlineData("ID=ubuntu\nVERSION_ID=latest")]
    [InlineData("ID=ubuntu\nVERSION_ID=\"24.04")]
    public void Linux_os_release_enricher_fails_closed_for_conflicting_or_invalid_versions(
        string transcript)
    {
        var detected = new DetectionEngine().Detect(
            transcript,
            new[] { BuiltInIdentificationRules.LinuxOsReleaseId });

        var result = new LinuxOsReleaseVersionEnricher().Enrich(transcript, detected);

        Assert.Null(Assert.Single(result.Candidates).Version);
    }
}
