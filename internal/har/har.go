// Package har parses HTTP Archive (HAR) files into the authenticated-context
// signals a security assessment needs: the endpoints actually exercised, the
// parameters seen on them, and the session credentials carried in the requests.
//
// This is the foundation for the biggest practical edge an autonomous scanner
// can have — starting from a real, logged-in session instead of rediscovering
// everything from an unauthenticated URL. The agent's ingest_har tool feeds the
// output here into the scan's session auth and the hypothesis ledger.
package har

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// HAR is the minimal subset of the HAR 1.2 schema we consume.
type HAR struct {
	Log struct {
		Entries []Entry `json:"entries"`
	} `json:"log"`
}

// Entry is one recorded request/response pair.
type Entry struct {
	Request Request `json:"request"`
}

// Request is the recorded request.
type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Headers     []NameValue `json:"headers"`
	QueryString []NameValue `json:"queryString"`
	Cookies     []NameValue `json:"cookies"`
	PostData    *PostData   `json:"postData,omitempty"`
}

// PostData is the request body descriptor.
type PostData struct {
	MimeType string      `json:"mimeType"`
	Text     string      `json:"text"`
	Params   []NameValue `json:"params"`
}

// NameValue is a HAR name/value pair (header, query param, cookie, post param).
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// EndpointInfo is one unique (method, scheme://host/path) surface with the
// union of parameter names observed on it.
type EndpointInfo struct {
	Method string
	URL    string // scheme://host/path (no query)
	Host   string
	Path   string
	Params []string
}

// authHeaderNames are request headers that carry a session/identity and are
// worth replaying so the scan is authenticated. Matched case-insensitively.
var authHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-access-token":      true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
	"authentication":      true,
	"proxy-authorization": true,
}

// Parse decodes HAR bytes. It tolerates the common wrapping where the HAR is a
// bare {"log":{...}} object.
func Parse(data []byte) (*HAR, error) {
	var h HAR
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("invalid HAR JSON: %w", err)
	}
	if len(h.Log.Entries) == 0 {
		return nil, fmt.Errorf("HAR contains no entries")
	}
	return &h, nil
}

// Endpoints returns the unique (method, scheme://host/path) surfaces with the
// union of parameter names (query + body) seen on each, sorted for stability.
// Static asset requests (images/fonts/styles/scripts) are skipped — they are
// not interesting attack surface.
func (h *HAR) Endpoints() []EndpointInfo {
	type acc struct {
		info   EndpointInfo
		params map[string]bool
	}
	byKey := map[string]*acc{}
	var order []string

	for i := range h.Log.Entries {
		req := h.Log.Entries[i].Request
		u, err := url.Parse(strings.TrimSpace(req.URL))
		if err != nil || u.Host == "" {
			continue
		}
		if isStaticAssetPath(u.Path) {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(req.Method))
		if method == "" {
			method = "GET"
		}
		base := u.Scheme + "://" + u.Host + u.Path
		key := method + " " + base
		a := byKey[key]
		if a == nil {
			a = &acc{
				info:   EndpointInfo{Method: method, URL: base, Host: u.Host, Path: u.Path},
				params: map[string]bool{},
			}
			byKey[key] = a
			order = append(order, key)
		}
		for _, q := range req.QueryString {
			if n := strings.TrimSpace(q.Name); n != "" {
				a.params[n] = true
			}
		}
		// Query params embedded in the URL but not in queryString.
		for n := range u.Query() {
			if n = strings.TrimSpace(n); n != "" {
				a.params[n] = true
			}
		}
		if req.PostData != nil {
			for _, p := range req.PostData.Params {
				if n := strings.TrimSpace(p.Name); n != "" {
					a.params[n] = true
				}
			}
			// JSON body keys (top level) are useful parameters too.
			for _, n := range topLevelJSONKeys(req.PostData) {
				a.params[n] = true
			}
		}
	}

	sort.Strings(order)
	out := make([]EndpointInfo, 0, len(order))
	for _, key := range order {
		a := byKey[key]
		params := make([]string, 0, len(a.params))
		for p := range a.params {
			params = append(params, p)
		}
		sort.Strings(params)
		a.info.Params = params
		out = append(out, a.info)
	}
	return out
}

// AuthHeaders returns the session/identity headers to replay, taken from the
// most recent entry that carries any (later entries reflect the fully
// authenticated state). Cookies are assembled from the Cookies array when no
// explicit Cookie header is present.
func (h *HAR) AuthHeaders() map[string]string {
	merged := map[string]string{}
	for i := range h.Log.Entries {
		req := h.Log.Entries[i].Request
		for _, hdr := range req.Headers {
			name := strings.ToLower(strings.TrimSpace(hdr.Name))
			if authHeaderNames[name] && strings.TrimSpace(hdr.Value) != "" {
				// Accumulate across entries; a later entry's value for the same
				// header wins (reflecting the freshest authenticated state).
				merged[canonicalHeader(hdr.Name)] = hdr.Value
			}
		}
		if _, hasCookie := merged["Cookie"]; !hasCookie && len(req.Cookies) > 0 {
			var parts []string
			for _, c := range req.Cookies {
				if strings.TrimSpace(c.Name) != "" {
					parts = append(parts, c.Name+"="+c.Value)
				}
			}
			if len(parts) > 0 {
				merged["Cookie"] = strings.Join(parts, "; ")
			}
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// InScopeEndpoints filters endpoints to those whose host matches (or is a
// subdomain of) the given target host. An empty target returns all endpoints.
func (h *HAR) InScopeEndpoints(targetHost string) []EndpointInfo {
	targetHost = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(targetHost, "https://"), "http://")))
	if i := strings.IndexByte(targetHost, '/'); i >= 0 {
		targetHost = targetHost[:i]
	}
	if h2, _, err := splitHostPort(targetHost); err == nil {
		targetHost = h2
	}
	all := h.Endpoints()
	if targetHost == "" {
		return all
	}
	out := make([]EndpointInfo, 0, len(all))
	for _, e := range all {
		host := strings.ToLower(e.Host)
		if hh, _, err := splitHostPort(host); err == nil {
			host = hh
		}
		if host == targetHost || strings.HasSuffix(host, "."+targetHost) {
			out = append(out, e)
		}
	}
	return out
}

// --- helpers ---

func canonicalHeader(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization":
		return "Authorization"
	case "cookie":
		return "Cookie"
	default:
		return strings.TrimSpace(name)
	}
}

func isStaticAssetPath(p string) bool {
	p = strings.ToLower(p)
	for _, ext := range []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func topLevelJSONKeys(pd *PostData) []string {
	if pd == nil || !strings.Contains(strings.ToLower(pd.MimeType), "json") {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(pd.Text), &m) != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// splitHostPort is net.SplitHostPort with a nil-safe wrapper that returns the
// host unchanged when there is no port.
func splitHostPort(hostport string) (host, port string, err error) {
	if !strings.Contains(hostport, ":") {
		return hostport, "", nil
	}
	i := strings.LastIndexByte(hostport, ':')
	return hostport[:i], hostport[i+1:], nil
}
