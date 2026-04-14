package com.google.tsunami.plugins.detectors.rce.cve202342793;

import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;

import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "TeamCityAuthBypassDetector",
    version = "0.1",
    description = "Detects CVE-2023-42793, RCE via auth bypass.",
    author = "ops",
    bootstrapModule = TeamCityAuthBypassDetectorBootstrapModule.class)
public final class TeamCityAuthBypassDetector {
  private static final Vulnerability VULN =
      Vulnerability.newBuilder()
          .setMainId(
              VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2023_42793"))
          .addRelatedId(
              VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-42793"))
          .build();
}
