# Changelog

## Release 0.1.1 (2026-06-29)

Adds discovery of Google's "templated" `.textproto` plugins, which the Java-only
discovery previously skipped entirely.

- `discover_plugins` now finds both Java `*Detector.java` detector directories and
  templated single-file `.textproto` plugins under `templated/templateddetector/plugins/`.
- CVEs are extracted from templated plugin filenames and structured `value:` fields
  (both dashed and underscore forms).
- Sightings for templated plugins link to the `/blob/master/` file URL; Java plugins
  keep the `/tree/master/` directory URL.
- Incremental mode no longer uses `--diff-filter=A`, so relocated/renamed plugins are
  no longer missed.
- End-to-end dry-run against upstream Tsunami plugins: 104 sightings emitted
  (84 Java + 20 templated).

## Release 0.1.0 (2026-04-14)

Initial release. Extracts CVE references from Google's Tsunami Security Scanner plugin repository and publishes sightings to Vulnerability-Lookup.

- End-to-end dry-run against upstream Tsunami plugins: 85 sightings emitted across 84 plugins.
