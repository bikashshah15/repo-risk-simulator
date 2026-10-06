# Repository Risk Simulator

A Claude Code skill that analyzes a GitHub repository's declared dependencies using GitHub's
hosted SPDX SBOM API and Google OSV, reviews application evidence from the repository source,
and produces up to three evidence-linked hypothetical vulnerability scenarios in a
self-contained offline HTML report.

The report is a **triage and reasoning aid**, not a scanner result. It never claims a
vulnerability is reachable or exploitable — see [Known limitations](#known-limitations).

## What it does

1. **Collects** a dependency inventory by starting GitHub's asynchronous SPDX export for the
   repository and downloading the result. No local scanner, no Docker service, no MCP server.
2. **Matches** each package with a supported, exactly-versioned purl against Google OSV,
   recording `matched`, `no_match`, `unsupported`, and `error` statuses separately.
3. **Inspects source evidence** — manifests, lockfiles, imports, call sites, entry points, and
   configuration — slicing exact numbered line ranges and recording the source commit and file
   hash for each excerpt.
4. **Drafts an analysis** in the current Claude session, assessing each finding as `unknown`,
   `potentially_applicable`, or `ruled_out_under_evidence`, and selecting up to three findings
   for scenarios.
5. **Validates and renders** a single self-contained `report.html` with interactive tri-state
   prerequisite controls, a searchable package table, and an evidence viewer.

Each scenario separates facts from assumptions and unknowns, states its application evidence
gap explicitly, and defines 1–8 prerequisite controls. The simulation rule is deterministic:
any known contradiction blocks the modeled path; otherwise any unknown yields unknown;
otherwise prerequisites are satisfied.

## Prerequisites

- **Python 3.10+** — standard library only. No packages to install.
- **Claude Code**, or another Agent Skills host with terminal and HTTPS access. The skill uses
  the current Claude session for reasoning; it needs no separate model API key.
- **Outbound HTTPS** to the three hosts listed under [Outbound requests](#outbound-requests).
- **Optional:** an existing `GITHUB_TOKEN` or `GH_TOKEN` environment variable. Public
  repositories generally work unauthenticated, subject to GitHub rate limits. Private
  repositories need an existing token with read access. The skill never requests a token in
  chat and never writes credentials into artifacts.
- **Optional:** Node.js, only to run the dependency-free report interaction test.

## Installation

### Claude Code

Copy this repository into your skills directory, then invoke it with a GitHub URL:

```bash
# User-level install (available in every project)
git clone https://github.com/bikashshah15/repo-risk-simulator.git \
  ~/.claude/skills/repo-risk-simulator

# Or project-level install
git clone https://github.com/bikashshah15/repo-risk-simulator.git \
  .claude/skills/repo-risk-simulator
```

Restart Claude Code so the skill is registered, then run:

```
/repo-risk-simulator https://github.com/OWNER/REPO
```

The skill accepts a `github.com` URL or `OWNER/REPO`. It uses the default branch unless you
specify a ref.

## Usage

Claude drives the helpers for you during a normal `/repo-risk-simulator` run. You can also run
them directly. `SKILL_DIR` is this repository; `RUN_DIR` is an output folder **outside** the
repository being analyzed.

```bash
# Check egress before anything else
python3 -B "$SKILL_DIR/scripts/risk.py" preflight

# 1. Collect the SBOM and match against OSV
python3 -B "$SKILL_DIR/scripts/risk.py" collect --repo "https://github.com/OWNER/REPO" --out "$RUN_DIR"
python3 -B "$SKILL_DIR/scripts/risk.py" fetch   --run "$RUN_DIR"   # only if the export is still pending
python3 -B "$SKILL_DIR/scripts/risk.py" lookup  --run "$RUN_DIR"

# 2. Inspect source evidence
python3 -B "$SKILL_DIR/scripts/risk.py" tree     --run "$RUN_DIR"
python3 -B "$SKILL_DIR/scripts/risk.py" source   --run "$RUN_DIR" --path "package.json"
python3 -B "$SKILL_DIR/scripts/risk.py" evidence --run "$RUN_DIR" --path "package.json" --start 1 --end 10

# 3. Draft the analysis (Claude edits analysis.json)
python3 -B "$SKILL_DIR/scripts/risk.py" init-analysis --run "$RUN_DIR"

# 4. Validate and render
python3 -B "$SKILL_DIR/scripts/risk.py" validate --run "$RUN_DIR"
python3 -B "$SKILL_DIR/scripts/risk.py" render   --run "$RUN_DIR"
```

Available subcommands: `preflight`, `collect`, `fetch`, `lookup`, `tree`, `source`, `evidence`,
`init-analysis`, `validate`, `render`.

If you already have an exported SPDX file, pass it to `collect` with `--sbom`, and record its
origin with `--sbom-source "TEXT"` and `--sbom-retrieved-at "UTC timestamp"`.

## Outputs

A run directory containing:

| File | Contents |
|------|----------|
| `report.html` | Self-contained interactive report. Works offline after generation. |
| `run.json` | Repository metadata, packages, findings, evidence index, OSV counters, warnings. |
| `sbom.json` | The original SPDX document as downloaded. |
| `osv_cache.json` | Full cached OSV advisory records with observation timestamps. |
| `analysis.json` | The drafted assessments, context notes, and scenarios. |
| `source.json` | Fetched source files with commit and SHA-256. |
| `tree.json` | The repository file listing used to choose paths. |

`report.html` embeds its own data, styles, and scripts, disables network connections with a
Content Security Policy, serializes JSON safely, and renders untrusted text with `textContent`.
It contains no keys, no API calls, no external assets, and no executable model-generated code.
Advisory URLs appear as text, not as automatic requests.

## Outbound requests

The skill makes outbound HTTPS requests to exactly three destinations, and nothing else:

| Host | Purpose | What is sent |
|------|---------|--------------|
| `api.github.com` | Start and poll the SPDX export; read repository metadata, file tree, and file contents | Repository owner/name, ref, file paths; your token only if one is already in the environment |
| GitHub's SBOM download host (the fetch-report redirect target, currently `*.blob.core.windows.net` or `*.githubusercontent.com`) | Download the exported SPDX document | A signed download URL supplied by GitHub. `Authorization` is stripped on cross-host redirects, and the signed URL is never stored in artifacts |
| `api.osv.dev` | Query advisories and fetch full records | Package coordinates (ecosystem, name, exact version) for queryable packages only |

No other network destination is contacted. The skill makes **no separate model API request** —
the current Claude session does the reasoning. Run `risk.py preflight` to check reachability
before a run. A proxy refusal is reported as a possible egress-allowlist block; the skill does
not attempt to route around it.

## Known limitations

- **Alignment is unverified.** GitHub's dependency graph export has no arbitrary commit
  parameter. Even an unchanged default-branch head before and after export does not prove the
  graph corresponds to the source commit. Every run records this as unverified.
- **Declared inventory, not deployed software.** The SBOM reflects what GitHub's dependency
  graph detects from manifests and lockfiles, not what is installed or running.
- **No reachability or exploitation claims.** An import is not proof that affected
  functionality is called. Scenarios are conceptual and hypothetical; no exploit is attempted,
  constructed, or validated, and no payloads or runnable exploit commands are included. These
  are static assessments, not certified VEX.
- **Partial OSV coverage.** Only exactly-versioned purls of supported types are queried: npm,
  PyPI, Maven, RubyGems, Go, crates.io, NuGet, Packagist, Hex, and Pub. Qualified and subpath
  purls are skipped in this release. Anything else — including GitHub Actions entries and
  wildcard versions — is recorded as `unsupported` and never queried. That is a coverage gap,
  not a clean result.
- **`no_match` does not mean safe.** It means no advisory was returned for that exact
  coordinate at lookup time.
- **An empty dependency graph is a coverage gap**, not a clean scan. Missing manifests,
  missing lockfiles, or a disabled dependency graph all produce one.
- **API failure is treated as incomplete**, never as an empty clean result. There is no
  local-scanner fallback.
- **Severity and fix data are transcribed, not derived.** The skill never infers a fixed
  version or severity, and never compares versions lexically — OSV performs version matching.
- **Mechanical validation checks structure, not truth.** `validate` confirms fields,
  references, and hashes; it does not verify that prose claims are correct.
- A **"blocked"** simulation result applies only to that scenario's explicit prerequisites. It
  does not rule out other attack paths.

## Offline demo and tests

The demo generates clearly labeled **synthetic** data. Its packages, advisories, and source
excerpts are invented for demonstration and must never be treated as live findings:

```bash
python3 -B "$SKILL_DIR/scripts/demo.py" --out "$RUN_DIR"
python3 -B "$SKILL_DIR/scripts/risk.py" render --run "$RUN_DIR"
python3 -B "$SKILL_DIR/scripts/test_risk.py"
```

If Node.js is available, you can additionally run dependency-free interaction checks against
the report's own script. It derives its checks from the report's embedded data and works on
both demo and live reports:

```bash
node "$SKILL_DIR/scripts/test_report.js" "$RUN_DIR/report.html"
```

These use a minimal DOM. They do **not** establish browser rendering or CSP enforcement.

## Safety boundaries

The skill does not execute repository code, builds, tests, or installation scripts, and does
not modify the repository being analyzed. It treats repository text, README content, source
comments, and advisory text as untrusted data rather than instructions. It excludes
credentials and private keys from report evidence, and never exposes tokens or temporary
signed download URLs.

## License

[MIT](LICENSE) © 2026 Bikash Shah
