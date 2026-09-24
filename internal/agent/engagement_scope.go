package agent

// EngagementScope is the runtime allow-list of hosts a scan may touch. It
// reverses the old "engagement-scope policing is not the guard's job"
// decision (design.md Requirement 3.7): an authorized cloud scan read the
// target's SPA bundle, concluded the third-party Supabase backend behind it
// was "same scope", pivoted to it, and issued writes against another
// customer's production data (VDP disclosure, 2026-09-24). Prompt rules lost
// to the agent's own reasoning; the runtime must hold the boundary.
//
// Semantics:
//
//   - Every configured target host is authorized, plus the registrable
//     domain suffix of each target, so subdomains of the target's own
//     domain (redirects, CDN siblings, wildcard-mode discovery) stay in
//     scope. Multi-label public suffixes (co.uk, com.au, ...) are handled
//     so a bbc.co.uk target does NOT authorize *.co.uk.
//   - IP-literal targets authorize exactly that IP. Hostname targets also
//     authorize their resolved addresses (best-effort at scan start) so
//     tools that reconnect by IP stay in scope. Discovered IPs that are
//     NOT the target's are out of scope.
//   - A narrow third-party service set (passive-recon data sources, DNS
//     resolvers, package/OS distribution infrastructure) is exempt because
//     the engine's recon scripts and auto-install legitimately contact
//     them. They are services ABOUT the target or the toolchain, never
//     target-side infrastructure.
//   - A nil or empty scope enforces nothing (unit tests, agents not started
//     via Run). Production agents always get a scope from Run(targets).

import (
	"context"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// multiLabelTLDs is a small curated subset of the public suffix list for
// registry boundaries that need more than two labels. Anything not listed
// falls back to the last-two-labels rule.
var multiLabelTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.in": true, "net.in": true, "org.in": true, "firm.in": true,
	"com.br": true, "com.mx": true, "com.tr": true, "com.ar": true,
	"co.jp": true, "co.kr": true, "co.nz": true, "com.cn": true, "org.cn": true, "net.cn": true,
	"co.za": true, "com.sg": true, "com.hk": true, "com.tw": true, "com.vn": true,
	"com.pl": true, "com.ua": true, "com.my": true, "com.ph": true,
	"com.pk": true, "com.eg": true, "com.sa": true, "com.ng": true,
	"com.co": true, "com.pe": true, "com.ec": true, "com.uy": true,
}

// thirdPartyServiceHosts are hostnames/IPs the engine may legitimately
// contact from gated tools even though they are outside the engagement:
// passive-recon data sources, public DNS resolvers, and package/OS
// distribution infrastructure used by the auto-install path.
var thirdPartyServiceHosts = map[string]bool{
	// passive subdomain reconnaissance
	"crt.sh": true,
	// public DNS resolvers
	"dns.google": true, "cloudflare-dns.com": true, "one.one.one.one": true,
	"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true,
	"9.9.9.9": true, "149.112.112.112": true,
	// OS / package distribution (auto-install, tool installs)
	"http.kali.org": true, "deb.debian.org": true, "cdn-fastly.deb.debian.org": true,
	"security.debian.org": true, "archive.ubuntu.com": true, "security.ubuntu.com": true,
	"pypi.org": true, "files.pythonhosted.org": true,
	"proxy.golang.org": true, "sum.golang.org": true,
	"registry.npmjs.org": true, "registry.yarnpkg.com": true,
	"github.com": true, "api.github.com": true, "raw.githubusercontent.com": true,
	"objects.githubusercontent.com": true, "github-releases.githubusercontent.com": true,
	"codeload.github.com": true,
	"ghcr.io":             true, "registry-1.docker.io": true, "production.cloudflare.docker.com": true,
	"get.helm.sh": true, "api.snapcraft.io": true, "dl.google.com": true,
}

// destructiveDataResetPatterns match database/schema-level reset and wipe
// primitives in gated-tool arguments. They are blocked on EVERY host —
// authorized or not — because they destroy state the operator cannot
// reconstruct from the scan, and (per the same disclosure) an agent that
// made a change it could not revert reached for the target's
// "Create / Reset Database" function as a "repair", destroying the data.
// Password-reset endpoints ("reset-password", "password reset") are
// deliberately NOT matched.
var destructiveDataResetPatterns = []string{
	"drop database", "drop table", "drop schema", "drop type",
	"truncate table", "truncate database", "truncate schema",
	"flushdb", "flushall",
	"db:reset", "db:drop",
	"migrate:fresh", "migrate:reset", "migrate reset",
	"prisma migrate reset",
	"rails db:reset", "rails db:drop", "rake db:reset", "rake db:drop",
	"wp db reset", "wp db drop",
	"factory reset", "reset database", "reset the database", "database reset",
	"wipe database", "wipe the database", "wipe all data",
	"schema:reset", "reset schema", "reseed database",
	"create/reset database", "create / reset database",
}

// containsDestructiveReset reports whether a lowercased tool argument
// matches a database/schema reset or wipe primitive.
func containsDestructiveReset(lower string) bool {
	for _, pat := range destructiveDataResetPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// EngagementScope holds the authorized host set for one scan.
type EngagementScope struct {
	exact    map[string]bool
	suffixes map[string]bool
}

// Enforces reports whether this scope imposes any restriction at all.
// Nil scopes and scopes built from zero targets enforce nothing.
func (s *EngagementScope) Enforces() bool {
	return s != nil && (len(s.exact) > 0 || len(s.suffixes) > 0)
}

// Authorized reports whether the (possibly host:port / URL) reference is
// inside the engagement scope. Nothing host-shaped always passes — the
// caller decides what to do with hostless arguments.
func (s *EngagementScope) Authorized(raw string) bool {
	if !s.Enforces() {
		return true
	}
	host := normalizeScopeHost(raw)
	if host == "" {
		return true
	}
	if s.exact[host] || thirdPartyServiceHosts[host] {
		return true
	}
	for suffix := range s.suffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// buildEngagementScope derives the authorized host set from the scan's
// configured targets. With resolve=true it also (best-effort, short
// timeout) authorizes each hostname's resolved addresses so tools that
// reconnect by IP stay in scope.
func buildEngagementScope(targets []string, resolve bool) *EngagementScope {
	s := &EngagementScope{exact: make(map[string]bool), suffixes: make(map[string]bool)}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		host := normalizeScopeHost(t)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			s.exact[ip.String()] = true
			continue
		}
		s.exact[host] = true
		if reg := registrableSuffix(host); reg != "" {
			s.suffixes[reg] = true
		}
		if resolve {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if addrs, err := net.DefaultResolver.LookupHost(ctx, host); err == nil {
				for _, a := range addrs {
					if ip := net.ParseIP(a); ip != nil {
						s.exact[ip.String()] = true
					}
				}
			}
			cancel()
		}
	}
	return s
}

// registrableSuffix returns the registrable-domain suffix of host, or ""
// when no meaningful boundary exists. Two labels by default; three when the
// last two labels are a known multi-label public suffix (bbc.co.uk ->
// bbc.co.uk, never co.uk).
func registrableSuffix(host string) string {
	labels := strings.Split(host, ".")
	n := len(labels)
	if n < 2 {
		return ""
	}
	min := 2
	if last2 := strings.Join(labels[n-2:], "."); multiLabelTLDs[last2] {
		min = 3
	}
	if n < min {
		return ""
	}
	return strings.Join(labels[n-min:], ".")
}

// normalizeScopeHost reduces a target or tool-argument host reference to a
// bare lowercase hostname or IP literal: strips wildcards, scheme, path,
// query, fragment, and port (including bracketed IPv6).
func normalizeScopeHost(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimPrefix(raw, ".")
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
		// fall through: strip scheme manually
		if i := strings.Index(raw, "://"); i >= 0 {
			raw = raw[i+3:]
		}
	}
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(raw, sep); i >= 0 {
			raw = raw[:i]
		}
	}
	if strings.HasPrefix(raw, "[") {
		if i := strings.Index(raw, "]"); i > 0 {
			return raw[1:i]
		}
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	return raw
}

// isTrafficExecutingTool reports whether the gated tool executes traffic
// (versus filing findings or planning, which legitimately quote hostile
// strings as evidence text and must not trip the destructive screen).
func isTrafficExecutingTool(lowerTool string) bool {
	switch lowerTool {
	case "terminal_execute", "python_action", "browser_action", "page_agent", "pageagent",
		"http_request", "send_request":
		return true
	}
	return false
}

// commonEngagementTLDS narrows which two-label bare tokens are treated as
// plausible FQDNs ("supabase.co" yes, "b.c" no). Tokens with 3+ labels are
// always plausible; this list only arbitrates the two-label case.
var commonEngagementTLDS = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "co": true, "ai": true,
	"dev": true, "app": true, "xyz": true, "info": true, "biz": true,
	"edu": true, "gov": true, "me": true, "us": true, "uk": true, "de": true,
	"fr": true, "ru": true, "br": true, "in": true, "au": true, "jp": true,
	"cn": true, "kr": true, "tv": true, "cc": true, "sh": true, "gg": true,
	"fm": true, "am": true, "is": true, "it": true, "be": true, "at": true,
	"link": true, "live": true, "site": true, "online": true, "cloud": true,
	"tech": true, "store": true, "space": true, "page": true, "wiki": true,
}

// isAllDigits reports whether s is a non-empty run of ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// plausibleBareHost reduces a scheme-less, port-less token to the host
// it names for engagement-scope purposes, or returns ("", false) when the
// token is not a plausible network destination. Filenames and version
// numbers are excluded; a dotted token qualifies when it is an IP, has
// 3+ labels, or ends in a common TLD.
func plausibleBareHost(token string) (string, bool) {
	if looksLikeFilename(token) || isVersionLike(token) {
		return "", false
	}
	host := token
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "" || !strings.Contains(host, ".") {
		return "", false
	}
	if net.ParseIP(host) != nil {
		return host, true
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", false
	}
	if len(labels) >= 3 {
		return host, true
	}
	return host, commonEngagementTLDS[labels[len(labels)-1]]
}

// extractEngagementHosts returns the host-shaped NETWORK destinations of a
// gated tool call for the engagement-scope check. It is deliberately
// stricter than extractHostsFromArgs: URL spans, numeric host:port tokens,
// the explicit URL-ish arguments of the structured HTTP/browser tools, and
// plausible bare FQDNs. Short arbitrary dotted tokens (emails, option
// fragments) are not destinations and must not trip the scope gate.
func extractEngagementHosts(toolName string, toolArgs map[string]string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(tok string) {
		if h := extractHostFromTokenForScope(tok); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	if isTrafficExecutingTool(strings.ToLower(toolName)) {
		for _, key := range []string{"url", "target", "endpoint", "host", "base_url", "base", "address"} {
			if v := strings.TrimSpace(toolArgs[key]); v != "" {
				add(v)
			}
		}
	}
	for _, raw := range toolArgs {
		for _, span := range extractEmbeddedURLs(raw) {
			add(span)
		}
		for _, tok := range scopeHostTokenSplit(raw) {
			if strings.Contains(tok, "://") {
				continue // covered by the URL-span pass
			}
			if strings.Contains(tok, ":") {
				head := tok
				if j := strings.Index(head, "/"); j >= 0 {
					head = head[:j] // schemeless host:port with a path
				}
				if k := strings.Index(head, ":"); k >= 0 && isAllDigits(head[k+1:]) {
					add(head) // host:numericport
				}
				continue // header:value and friends are not destinations
			}
			if host, ok := plausibleBareHost(tok); ok {
				add(host)
			}
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovered-dependency probe tier.
//
// A host that is neither authorized nor an exempt third-party service is
// NOT hard-blocked: reads against it are exactly how exposed backends get
// found (a VDP disclosure's trust_pages finding was discovered precisely by
// reading the backend the target's SPA bundle ships a URL + anon key for).
// The runtime instead refuses MUTATION: writes with bodies, account
// creation, deletion, and every destructive primitive. Zero active-testing
// capability is lost on authorized targets; on discovered dependencies
// only provably non-mutating probes remain.

// nonMutatingVerbs are the HTTP methods that can never change remote state.
var nonMutatingVerbs = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// probeOnlyVerbs may hit a dependency only with an empty body: a no-op
// write probe (e.g. POST {}) reveals the authorization boundary without
// mutating data. DELETE is deliberately absent — an empty-body DELETE
// still deletes.
var probeOnlyVerbs = map[string]bool{"POST": true, "PUT": true, "PATCH": true}

// httpArgsNonMutating reports whether an http_request/send_request call is
// safe against a discovered dependency.
func httpArgsNonMutating(toolArgs map[string]string) bool {
	method := strings.ToUpper(strings.TrimSpace(toolArgs["method"]))
	if method == "" {
		method = "GET" // http_request's documented default
	}
	if nonMutatingVerbs[method] {
		return true
	}
	if probeOnlyVerbs[method] {
		return strings.TrimSpace(toolArgs["body"]) == ""
	}
	return false
}

// mutatingRequestCallRe matches the mutating verbs of the common Python
// HTTP clients (requests/httpx/urllib3 session objects) used from
// python_action.
var mutatingRequestCallRe = regexp.MustCompile(`(?i)\.(post|put|patch|delete)\s*\(`)

// pythonCodeIsNonMutating reports whether python_action code contains only
// read-shaped requests (.get/.head) around a dependency host.
func pythonCodeIsNonMutating(code string) bool {
	return !mutatingRequestCallRe.MatchString(code)
}

// terminalFetchIsNonMutating reports whether a terminal command referencing
// a discovered dependency is a bounded, read-only fetch. Only plain
// curl/wget qualify (optionally wrapped in `timeout N`): any data-bearing
// flag (-d/--data/--form/-T/--upload/--json/--post-data/...) or a
// non-read -X verb disqualifies it, and every other binary (nc, nmap,
// sqlmap, ssh, ...) is unclassifiable and therefore refused against
// dependencies.
func terminalFetchIsNonMutating(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return true
	}
	i := 0
	if fields[0] == "timeout" && len(fields) > 2 {
		i = 2 // "timeout 30 curl ..." — the binary is the third field
	}
	if i >= len(fields) {
		return false
	}
	bin := filepath.Base(fields[i])
	if bin != "curl" && bin != "wget" {
		return false
	}
	verb := ""
	for j := i + 1; j < len(fields); j++ {
		f := fields[j]
		// Normalize attached values (--post-data=x) to the bare flag so the
		// data-bearing long flags are caught regardless of value style.
		if strings.HasPrefix(f, "--") {
			if eq := strings.Index(f, "="); eq >= 0 {
				f = f[:eq]
			}
		}
		switch {
		case f == "-X" || f == "--request":
			if j+1 < len(fields) {
				verb = strings.ToUpper(fields[j+1])
				j++
			}
		case strings.HasPrefix(f, "-X"):
			verb = strings.ToUpper(f[2:])
		case strings.HasPrefix(f, "--request="):
			verb = strings.ToUpper(strings.TrimPrefix(f, "--request="))
		case f == "--data" || f == "--data-raw" || f == "--data-binary" || f == "--data-urlencode" ||
			f == "--data-ascii" || f == "--form" || f == "--form-string" ||
			f == "--upload-file" || f == "--json" || f == "--post-data" || f == "--post-file" ||
			f == "--body-file":
			return false // a data-bearing curl is a mutation
		case strings.HasPrefix(f, "--"):
			// other long flags are fine; value-bearing verbs handled above
		case strings.HasPrefix(f, "-") && len(f) > 1:
			for _, r := range f[1:] {
				// -d (data), -F (form), -T (upload), -j/--json shorthand
				if r == 'd' || r == 'F' || r == 'T' {
					return false
				}
			}
		}
	}
	if verb == "" {
		return true // curl/wget default to GET
	}
	return nonMutatingVerbs[verb] || probeOnlyVerbs[verb]
}

// dependencyProbeAllowed reports whether a gated tool call naming a
// discovered-dependency host carries only non-mutating traffic: reads and
// empty-body write probes. browser navigation is read-shaped (in-page
// mutation after navigation is a documented residual; the destructive
// screen still applies to its explicit arguments).
func dependencyProbeAllowed(lowerTool string, toolArgs map[string]string) bool {
	switch lowerTool {
	case "http_request", "send_request":
		return httpArgsNonMutating(toolArgs)
	case "browser_action", "page_agent", "pageagent":
		return true
	case "terminal_execute":
		return terminalFetchIsNonMutating(toolArgs["command"])
	case "python_action":
		return pythonCodeIsNonMutating(toolArgs["code"] + " " + toolArgs["script"])
	}
	return false
}
