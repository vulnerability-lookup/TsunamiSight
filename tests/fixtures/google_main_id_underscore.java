package com.google.tsunami.plugins.detectors.rce.cve202432113;

@PluginInfo(type = PluginType.VULN_DETECTION, name = "OfbizDetector",
    version = "0.1", description = "OFBiz RCE", author = "ops",
    bootstrapModule = OfbizBootstrapModule.class)
public final class OfbizDetector {
  Vulnerability v = Vulnerability.newBuilder()
      .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2024_32113"))
      .addRelatedId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-32113"))
      .build();
}
