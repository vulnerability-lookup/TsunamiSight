package com.google.tsunami.plugins.detectors.rce.cve20146271;

@PluginInfo(type = PluginType.VULN_DETECTION, name = "ShellshockDetector",
    version = "0.1", description = "Detects CVE-2014-6271 / CVE-2014-7169", author = "doyensec",
    bootstrapModule = ShellshockBootstrapModule.class)
public final class ShellshockDetector {
  Vulnerability v1 = Vulnerability.newBuilder()
      .setMainId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2014-6271"))
      .addRelatedId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2014-7169"))
      .build();
}
