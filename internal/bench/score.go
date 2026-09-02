package bench

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// Result is the outcome of running one challenge.
type Result struct {
	Name             string
	Class            string
	Solved           bool
	MatchedFindingID string
	Findings         int
	Elapsed          time.Duration
	Err              error
}

// Scorecard aggregates challenge results.
type Scorecard struct {
	Results []Result
}

// Total returns the number of challenges run.
func (s Scorecard) Total() int { return len(s.Results) }

// SolvedCount returns the number of challenges solved.
func (s Scorecard) SolvedCount() int {
	n := 0
	for _, r := range s.Results {
		if r.Solved {
			n++
		}
	}
	return n
}

// ByClass returns solved/total counts per vulnerability class.
func (s Scorecard) ByClass() map[string][2]int {
	out := map[string][2]int{}
	for _, r := range s.Results {
		c := out[r.Class]
		c[1]++
		if r.Solved {
			c[0]++
		}
		out[r.Class] = c
	}
	return out
}

// String renders a human-readable scorecard.
func (s Scorecard) String() string {
	var b strings.Builder
	total := s.Total()
	solved := s.SolvedCount()
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(solved) / float64(total)
	}
	fmt.Fprintf(&b, "Benchmark scorecard: %d/%d solved (%.0f%%)\n", solved, total, pct)
	for _, r := range s.Results {
		status := "FAIL"
		if r.Solved {
			status = "PASS"
		}
		fmt.Fprintf(&b, "  [%s] %-16s %-14s %2d finding(s)  %6.1fs", status, r.Name, r.Class, r.Findings, r.Elapsed.Seconds())
		if r.MatchedFindingID != "" {
			fmt.Fprintf(&b, "  -> %s", r.MatchedFindingID)
		}
		if r.Err != nil {
			fmt.Fprintf(&b, "  ERROR: %v", r.Err)
		}
		b.WriteByte('\n')
	}
	// Per-class line, sorted for stable output.
	byClass := s.ByClass()
	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	if len(classes) > 0 {
		b.WriteString("By class:")
		for _, c := range classes {
			fmt.Fprintf(&b, " %s %d/%d", c, byClass[c][0], byClass[c][1])
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Solved reports whether any finding proves the expected class on the expected
// endpoint, returning the matching finding's ID. This is the deterministic
// scoring primitive — no model involved.
func Solved(expectedClass, expectedEndpoint string, findings []reporting.Vulnerability) (bool, string) {
	want := canonicalClass(expectedClass)
	wantPath := endpointPath(expectedEndpoint)
	for _, f := range findings {
		if classifyFinding(f) != want {
			continue
		}
		if endpointMatches(wantPath, f.Endpoint) || endpointMatches(wantPath, f.Target) {
			return true, f.ID
		}
	}
	return false, ""
}

// classifyFinding maps a finding to a canonical vuln class using its title,
// description, and CWE. It is intentionally self-contained (not tied to the
// reporting package's private classifier) so the benchmark's notion of "right
// class" is explicit and stable.
func classifyFinding(f reporting.Vulnerability) string {
	text := strings.ToLower(f.Title + " " + f.Description)
	for _, m := range classKeywords {
		for _, kw := range m.keywords {
			if strings.Contains(text, kw) {
				return m.class
			}
		}
	}
	return cweClass(f.CWE)
}

type classMatch struct {
	class    string
	keywords []string
}

// classKeywords maps title/description keywords to canonical classes. Order
// matters only in that the first hit wins; keep the more specific phrases first.
var classKeywords = []classMatch{
	{"xss", []string{"xss", "cross-site scripting", "cross site scripting", "script injection"}},
	{"sqli", []string{"sql injection", "sqli", "sql inject", "union select", "blind sql"}},
	{"open_redirect", []string{"open redirect", "unvalidated redirect", "url redirect"}},
	{"idor", []string{"idor", "insecure direct object", "bola", "broken object level", "broken access control", "unauthorized access"}},
	{"ssrf", []string{"ssrf", "server-side request forgery", "server side request forgery"}},
	{"rce", []string{"remote code execution", "rce", "command injection", "os command", "code execution"}},
	{"lfi", []string{"local file inclusion", "lfi", "path traversal", "directory traversal"}},
	{"ssti", []string{"ssti", "template injection"}},
	{"xxe", []string{"xxe", "xml external entity"}},
	{"csrf", []string{"csrf", "cross-site request forgery"}},
}

// canonicalClass normalizes a class label to the benchmark's canonical set.
func canonicalClass(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	switch c {
	case "bola", "bfla":
		return "idor"
	case "openredirect", "open-redirect":
		return "open_redirect"
	default:
		return c
	}
}

// cweClass maps a CWE identifier to a canonical class, or "" when unmapped.
func cweClass(cwe string) string {
	switch firstDigits(cwe) {
	case "79":
		return "xss"
	case "89":
		return "sqli"
	case "601":
		return "open_redirect"
	case "918":
		return "ssrf"
	case "22":
		return "lfi"
	case "77", "78", "94":
		return "rce"
	case "611":
		return "xxe"
	case "352":
		return "csrf"
	case "1336":
		return "ssti"
	case "284", "285", "639", "862", "863", "566":
		return "idor"
	default:
		return ""
	}
}

// firstDigits returns the first run of digits in s (so "CWE-79" -> "79").
func firstDigits(s string) string {
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if start == -1 {
				start = i
			}
		} else if start != -1 {
			return s[start:i]
		}
	}
	if start != -1 {
		return s[start:]
	}
	return ""
}

// endpointMatches reports whether a finding's endpoint/target covers the
// expected path: exact match, or the expected path is a parent segment of the
// finding's path (so an IDOR reported on /api/orders/1042 matches the challenge
// endpoint /api/orders).
func endpointMatches(wantPath, findingLoc string) bool {
	got := endpointPath(findingLoc)
	if got == "" || wantPath == "" {
		return false
	}
	return got == wantPath || strings.HasPrefix(got, wantPath+"/")
}

// endpointPath reduces an endpoint or full URL to a normalized path: host and
// scheme stripped, query/fragment removed, trailing slash trimmed, lowercased.
func endpointPath(loc string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return ""
	}
	if strings.Contains(loc, "://") {
		if u, err := url.Parse(loc); err == nil {
			loc = u.Path
		}
	}
	if i := strings.IndexAny(loc, "?#"); i >= 0 {
		loc = loc[:i]
	}
	loc = strings.ToLower(loc)
	if len(loc) > 1 {
		loc = strings.TrimRight(loc, "/")
	}
	if loc == "" {
		return "/"
	}
	return loc
}
