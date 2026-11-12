# Improve detection accuracy before expanding coverage

Mobile Audit should first make its existing rules reliable, then add structured Android configuration checks and a small set of contextual code checks. This plan is based on repository inspection, not a scan of an APK or a measurement of production detection accuracy. The first implementation slice is complete; the remaining phases below are still planned.

## Implemented first slice

- Fixed per-candidate URL/schema filtering, strict canonical Base64 validation, evidence line boundaries, malware association isolation, and exact malware hostname matching.
- Compiled active rules once per scan; invalid rules are isolated and scans with skipped/failed detectors finish with a visible `Finished with detection errors` status.
- Repaired email, credential whitespace, connection and concatenated-alternative patterns. Email matching bounds local/domain lengths and rejects long separator-rich non-email input without quadratic rescanning. HTTP API usage is informational; generic TLS APIs no longer establish pinning.
- Added PKCS#8/encrypted/OpenSSH private-key envelope coverage and required private-key material for GCP service-account findings.
- Added bounded UTF-8 text asset secret scans (JSON, properties, JavaScript, text, HTML, YAML, INI and configuration files), with a default 2 MiB limit configurable through `DETECTION_MAX_ASSET_BYTES`. Oversized, binary and undecodable candidate text assets are reported as incomplete coverage.
- Added migration `0008_repair_detection_rules`: updates unchanged shipped rules while preserving customized patterns/fields; existing finding records are retained. Run `python manage.py migrate` for installed databases. Fresh installs receive the updated fixture.

Validation: 19 targeted Django tests pass in the running application container against an isolated in-memory SQLite database, including migration preservation/idempotency, per-scan rule loading, bounded asset coverage and positive/negative shipped-rule cases. The runner uses the normal URL configuration and disables logging configuration in memory. PDF rendering, live APK decompilation and the full application suite were not validated.

Remaining: stable semantic rule/extractor metadata and version provenance; structured manifest/network checks; contextual TLS/WebView analysis; broader severity calibration; result fingerprints, retry deduplication and corpus precision/recall measurement. Existing ID-based extraction remains compatible for this slice. Secret evidence redaction remains pending.

## Original baseline

The shipped fixture contains **85 patterns, all active** before this slice (86 after the added private-key rule): 74 use a finding severity and 11 use `NO` for positive practices. Installed database contents may differ. Existing coverage includes secrets, WebView usage, SQL calls, cryptography, explicit exported/debuggable/backup attributes, URLs, and capability indicators. These are improvements to existing coverage, not candidates for duplicate rules.

At planning time the pipeline applied regexes only to `.java`, `.kt`, and `.xml` files. The first slice adds bounded text asset secret scanning; there is still no separate contextual manifest detector.

| Evidence | Implication |
| --- | --- |
| [`analysis.py`](../app/analysis.py), lines 366–388 | File selection limits coverage; JSON, properties, JavaScript and other assets are outside pattern matching. |
| [`analysis.py`](../app/analysis.py), lines 416–422 | Active patterns are queried and compiled for every file; compilation happens outside the per-rule exception handler. |
| [`analysis.py`](../app/analysis.py), lines 427–459 | String classification depends on database numeric IDs; URL and Base64 handling contain false-negative paths. |
| [`models.py`](../app/models.py), lines 102–116 | Rules have regex/severity metadata but no stable semantic key, scope, confidence, or version. |
| [`data.json`](../app/fixtures/data.json), line 1 | Some rules confuse presence with a weakness: every HTTP client is high severity; `TrustManager`, `HostnameVerifier`, or `onReceivedSslError` can be reported as evidence of pinning. |
| [`tests.py`](../app/tests.py) | Existing tests cover decompilation and access controls; no direct tests of `find_patterns` or `get_match_lines` were found. |

## Phase 1 — Repair and characterize the current detector

**Priority: highest. Effort: medium. Dependency: none.** Deliver in small reviewable slices before adding new rules.

1. Add a detection fixture suite that loads the shipped patterns and checks compilation plus representative matching and nonmatching examples. Audit escaping and malformed entries: credential whitespace uses `s*` rather than `\s*`, the email expression uses literal `w`, the GCP service-account pattern contains a code-like fragment, and some alternatives are accidentally concatenated. Correct patterns deliberately; do not globally unescape them without regression examples.
2. Repair URL and Base64 extraction. The URL branch currently breaks out of the rule's match loop if the *whole file* contains `schemas.android.com`, skipping real endpoints in ordinary XML. Base64 re-encoding returns bytes but is compared with a matched string, so a successfully decoded candidate takes the break path; decoding exceptions are logged and terminate the remainder of that rule for the file. Validate each candidate independently and continue after rejected candidates.
3. Load and validate a rule snapshot once per scan; isolate invalid rules and surface partial analysis. Replace ID-specific behavior with stable rule keys and explicit extractor metadata while preserving existing foreign keys and finding history. Add version/provenance so results can be reproduced.
4. Separate informational inventory, suspicious usage, and evidence-backed weaknesses. Ordinary URLs, permissions, logging, SQL calls, and HTTP clients need context before receiving high severity. A trust-related symbol alone must not establish successful pinning.

**Acceptance:** every enabled rule compiles or is explicitly reported as skipped; one malformed rule cannot suppress subsequent valid rules. Every repaired rule has positive and negative cases. XML containing both a schema namespace and an API URL retains the endpoint. Valid Base64 produces extracted data and malformed candidates do not suppress later matches. Evidence line ranges are verified for first-line and multiline matches. A scan with skipped detectors is visibly incomplete rather than silently presented as fully analyzed.

## Phase 2 — Add structured manifest and network checks

**Priority: high. Effort: medium. Dependency: Phase 1 evidence and rule metadata.** Parse manifest/resource XML and resolve references rather than adding more attribute regexes.

| Rule family | New or improved behavior | Acceptance examples |
| --- | --- | --- |
| Component exposure | Upgrade the existing exported rule: resolve explicit/implicit exposure by component type and applicable SDK behavior, inherited/component permissions, and launcher intent. | Ordinary launcher entry points do not automatically become high severity. Unprotected exported services/providers retain component and permission evidence. Missing/unknown SDK values produce an explicit uncertainty. |
| Cleartext policy | New checks for effective cleartext allowance using manifest attributes plus inherited network security base/domain configuration. Keep endpoint inventory separate from proof of insecure communication. | Test domain exceptions, nested inheritance, absent attributes, target SDK defaults, and invalid/unresolved resources. A restrictive domain configuration overrides a permissive parent where applicable. |
| Trust configuration | New checks for custom user trust anchors and effective debug trust overrides, with scope and build context. | A debug override alone is not reported as active in a non-debuggable application; deliberate scoped custom trust remains contextual evidence, not an automatic critical finding. |

Also improve the existing debug and backup rules in this phase: report effective debuggability and backup/data extraction configuration with applicable platform context. `allowBackup=true` alone must not establish sensitive-data exposure; Android 12 device-to-device transfer behavior needs explicit treatment.

**Acceptance:** stable rule IDs, relevant manifest/resource snippets, component/domain scope, documented SDK assumptions, and positive/negative fixture pairs for each row. Avoid emitting both the old literal match and its structured replacement as duplicate vulnerabilities.

Platform references: [network security configuration](https://developer.android.com/privacy-and-security/security-config), [application manifest attributes](https://developer.android.com/guide/topics/manifest/application-element), [Android 12 behavior changes](https://developer.android.com/about/versions/12/behavior-changes-12). Resolve exact defaults and version boundaries against these sources during implementation.

## Phase 3 — Improve high-value code and secret rules

**Priority: high after Phase 2. Effort: medium to large. Dependency: rule fixtures and confidence model.** Add narrowly scoped syntax/context analysis before considering whole-program data flow.

| Rule family | Planned scope | False-positive boundary |
| --- | --- | --- |
| TLS validation bypass | Improve existing certificate/HTTP patterns to distinguish permissive trust implementations, unconditional hostname acceptance, and SSL-error continuation from ordinary secure API use. | Inspect method bodies and calls; class names/imports alone are insufficient. Unresolved behavior remains a review indicator. |
| Unsafe WebView configuration | Improve existing WebView detection with linked evidence for JavaScript bridges, file access, and external/untrusted content. | JavaScript enabled alone is a capability observation. Do not claim an exploit path without evidence that the relevant settings and content apply to the same WebView. |
| Embedded secrets | Expand bounded text scanning to JSON/properties/JS/assets, repair existing credential patterns, detect service-account private-key material and additional private-key envelope forms. | Provider endpoints, public identifiers, placeholders, and public keys are not automatically secrets. Use format/context checks, exclusions and confidence; redact sensitive evidence in exports. |

**Acceptance:** each detector includes vulnerable, safe, comment/import-only, multiline and decompiler-format variants. Findings distinguish observed code from inferred reachability; uncertain cases remain review items. Resource scans enforce size/type limits and do not attempt to decode arbitrary binaries as text.

## Phase 4 — Make results measurable and repeatable

**Priority: next. Effort: medium. Dependency: Phases 1–3.**

- Add fingerprints and scan-to-scan comparison for new, persistent and resolved findings. Preserve triage only when the matching evidence and rule identity support it; retries must not inflate counts.
- Record per-detector duration, files checked/skipped, rule version and errors. Aggregate ORM writes and cache compiled patterns using measured baselines rather than assumed speedups.
- Add reviewed mappings to current OWASP guidance while preserving the existing 2016 mapping history. Do not relabel historical findings silently.

**Acceptance:** deterministic fixture results, exact expected findings/severities, reported skipped coverage, and an agreed labeled APK corpus for measuring precision/recall. Establish a baseline before setting numerical improvement targets. Include a small integration APK exercising manifest parsing, resource resolution, decompilation and evidence persistence.

## Delivery boundary

Start with Phase 1's characterization suite and URL/Base64 corrections. Keep fixture repair, engine metadata, each structured detector, and contextual code rules as separately reviewable changes. Implementations that exceed the repository's 400 changed-line review budget should be split by these working boundaries.

Dynamic analysis, iOS support, whole-program taint analysis, dependency vulnerability feeds, and conclusions about exploitability are outside this first plan. A parser-based approach costs more than adding regexes, but enables context-aware checks; regexes remain useful for bounded discovery and secret formats.

The original plan was validated through read-only source and fixture inspection; first-slice verification is recorded above.
