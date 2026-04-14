package com.google.tsunami.plugins.detectors.credentials.weak;

@PluginInfo(type = PluginType.VULN_DETECTION, name = "GenericWeakCredentialDetector",
    version = "0.1", description = "Detects weak credentials on exposed services.",
    author = "google", bootstrapModule = GenericWeakCredentialDetectorBootstrapModule.class)
public final class GenericWeakCredentialDetector {
  Vulnerability v = Vulnerability.newBuilder()
      .setMainId(VulnerabilityId.newBuilder()
          .setPublisher("GOOGLE")
          .setValue("GENERIC_WEAK_CREDENTIAL"))
      .build();
}
