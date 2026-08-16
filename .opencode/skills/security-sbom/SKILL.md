---
name: security-sbom
description: >
  Generate and analyze Software Bill of Materials (SBOM) for supply chain
  vulnerability detection. Parses CycloneDX/SPDX formats, correlates
  components against NVD CVE database, identifies transitive dependency
  risks in Cargo/Rust projects, CDN resources (SRI verification),
  and static site generator dependencies. Calculates risk scores and
  generates compliance reports.
compatibility: opencode
---

# Security SBOM — Supply Chain Vulnerability Analysis

## What I do
- Generate SBOMs for Rust/Cargo projects and static site deployments
- Parse CycloneDX JSON and SPDX JSON formats
- Correlate components against NVD 2.0 API for known CVEs
- Identify transitive dependency risks and blast radius
- Verify Subresource Integrity (SRI) on CDN-loaded scripts (Giscus, highlight.js, Fuse.js)
- Check pinned versions and checksum verification in CI/CD workflows
- Calculate component risk scores using CVSS and dependency centrality
- Generate compliance reports (EO 14028, EU CRA)

## When to use me
- Project uses cargo-installed tools without version pinning (e.g., `cargo install marmite`)
- External CDN resources (Giscus, Fuse.js, highlight.js) lack `integrity` hashes
- CI/CD pipeline has broken or missing dependency caching (e.g., `hashFiles('**/Cargo.lock')` with no Cargo.lock)
- Need to assess supply chain risk for a static site or Rust-based SSG
- Regulatory requirement mandates SBOM analysis (EO 14028, EU Cyber Resilience Act)
- Third-party dependency review required before deployment

## Guidelines

### 1. Generate SBOM

For Rust/Cargo projects, generate a CycloneDX SBOM:

```bash
# If syft is available, scan the project directory
syft dir:. -o cyclonedx-json > sbom-cyclonedx.json

# Manual SBOM for cargo-installed tools
cargo install cargo-bom 2>/dev/null || cargo install cargo-bom
cargo bom > sbom-cargo.json
```

For CDN resources, enumerate all external scripts:

```bash
# Find all external script/src attributes in generated HTML
rg -o 'src="https?://[^"]*"' site/*.html
rg -o 'integrity="[^"]*"' site/*.html
```

### 2. Parse SBOM and Extract Components

Extract all components with PURL, CPE, and version:

```python
import json

def parse_sbom(path):
    with open(path) as f:
        sbom = json.load(f)
    fmt = sbom.get("bomFormat", sbom.get("spdxVersion", ""))
    if "CycloneDX" in fmt:
        return sbom.get("components", [])
    elif "SPDX" in fmt:
        return [{
            "name": p["name"],
            "version": p.get("versionInfo", ""),
            "purl": next(
                (r["referenceLocator"] for r in p.get("externalRefs", [])
                 if r["referenceType"] == "purl"),
                None
            )
        } for p in sbom.get("packages", [])]
    return []
```

### 3. Correlate with NVD CVE Database

Query NVD 2.0 API for each component:

```python
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cves(component_name, version, api_key=None):
    keyword = f"{component_name} {version}"
    params = {"keywordSearch": keyword, "resultsPerPage": 20}
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])
```

For each CVE returned, extract:
- CVE ID, CVSS score (v3 base score)
- Attack vector, complexity, privileges required
- Known exploits (CISA KEV catalog)
- Fix version if available

### 4. Verify Subresource Integrity (SRI)

Check every external `<script>` and `<link>` tag for `integrity` attribute:

```bash
# Find CDN resources without SRI
rg '<(script|link)[^>]*src="https://cdn' site/*.html | grep -v 'integrity='

# Generate SRI hash for a CDN resource
curl -sL <CDN_URL> | openssl dgst -sha384 -binary | openssl base64 -A
```

Flag all external resources missing SRI as MEDIUM severity findings.

### 4.1 License Compliance Check

Verify each component's license (MIT, Apache-2.0, GPL, AGPL) and flag copyleft licenses:

```bash
# Extract licenses from Cargo.toml/Cargo.lock
rg 'license\s*=' Cargo.toml 2>/dev/null || echo "No Cargo.toml"
# Use cargo-license if available
cargo license 2>/dev/null | grep -iE 'gpl|agpl'
```

Flag any GPL/AGPL components as INFO for awareness (may restrict commercial use).

### 4.2 Reproducible Builds Check

Verify that builds produce deterministic output:
- Check if `site/` contents match between two identical builds
- Use `diff -r` to compare build outputs

```bash
# Build twice and compare
marmite . /tmp/build1 && marmite . /tmp/build2
diff -r /tmp/build1 /tmp/build2
```

### 4.3 Typosquatting Risk Assessment

Check if installed package names mimic popular packages:

```bash
# Extract package names and check against known packages
rg 'name\s*=' Cargo.toml 2>/dev/null | rg -v 'marmite'
# Manual review: are any names likely typosquats?
```

### 5. Check CI/CD Supply Chain

Analyze GitHub Actions workflow for supply chain risks:

- **Unpinned tool versions**: `cargo install <tool>` without `--version <x.y.z>`
- **Broken cache keys**: `hashFiles('**/Cargo.lock')` when `Cargo.lock` does not exist in repo
- **Missing checksums**: No `sha256sum` verification after `cargo install`
- **Unpinned actions**: GitHub Actions using `@v4` (major version tag) instead of `@<full-sha>`

### 6. Build Dependency Graph

Identify transitive risks and blast radius:

```python
import networkx as nx

def build_graph(components, dependencies):
    G = nx.DiGraph()
    for c in components:
        G.add_node(c.get("purl", c["name"]), name=c["name"], version=c.get("version"))
    for dep in dependencies:
        parent = dep.get("ref")
        for child in dep.get("dependsOn", []):
            G.add_edge(parent, child)
    return G
```

Key metrics:
- **In-degree**: blast radius (more dependents = higher impact)
- **Shortest path to root**: exploitability (closer = easier to exploit)
- **Betweenness centrality**: bottleneck components

### 7. Calculate Risk Scores

```
Component Risk = max(CVSS scores of all CVEs affecting the component)
Weighted Risk = Component Risk × (1.0 + 0.1 × in_degree)
Overall SBOM Risk = weighted average by dependency centrality

Risk Levels:
  CRITICAL: CVSS >= 9.0 or CISA KEV listed
  HIGH:     CVSS >= 7.0
  MEDIUM:   CVSS >= 4.0
  LOW:      CVSS < 4.0
```

### 8. Generate Compliance Report

Produce a structured report with:
- SBOM metadata (format, version, analysis date, total components)
- Vulnerability summary (counts by severity)
- Critical findings table (CVE, CVSS, affected component, fix version, blast radius)
- SRI compliance status (PASS/FAIL per external resource)
- CI/CD supply chain risks (materials without provenance)
- Dependency graph risks (bottlenecks, deepest chains)
- Remediation prioritization

## Examples

### Scenario: Blog static site with Marmite SSG

1. Run `rg 'src="https://cdn' site/*.html` to find CDN resources
2. Check each for `integrity` attribute — flag missing SRI
3. Inspect `.github/workflows/*.yaml` for `cargo install` without `--version`
4. Verify `hashFiles('**/Cargo.lock')` against actual repo files
5. Generate SBOM for cargo dependencies: `cargo install cargo-bom && cargo bom`
6. Query NVD for known CVEs on marmite 0.2.6 and its transitive deps
7. Document all findings in a compliance-ready report

### Scenario: New dependency added to project

1. Regenerate SBOM
2. Diff against previous SBOM to identify new components
3. Query NVD for each new component
4. Check for dependency confusion risks (name squatting)
5. Calculate updated risk score
6. Report any new critical/high vulnerabilities
