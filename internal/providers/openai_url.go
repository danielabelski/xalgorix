package providers

import (
	"net/url"
	"regexp"
	"strings"
)

var apiVersionSegmentPattern = regexp.MustCompile(`(?i)^v[0-9]+(?:[a-z][a-z0-9._-]*)?$`)

// OpenAICompatibleURL appends an OpenAI-compatible resource path to apiBase.
//
// Most providers publish a host/root and expect Xalgorix to insert /v1, while
// others already include their API version in the base path. Z.AI is one such
// provider: its Coding Plan base ends in /v4 and chat requests must go to
// /v4/chat/completions, not /v4/v1/chat/completions. Treat any explicit
// version path segment (v1, v1beta, v4, ...) as authoritative and only insert
// /v1 when the base contains no version at all.
func OpenAICompatibleURL(apiBase, resource string) string {
	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	resource = strings.Trim(strings.TrimSpace(resource), "/")
	if resource == "" {
		return base
	}

	u, err := url.Parse(base)
	if err != nil {
		return strings.TrimRight(base, "/") + "/" + resource
	}

	path := strings.TrimRight(u.Path, "/")
	wantedSuffix := "/" + resource
	if strings.HasSuffix(strings.ToLower(path), strings.ToLower(wantedSuffix)) {
		return u.String()
	}
	if !hasAPIVersionSegment(path) {
		path += "/v1"
	}
	u.Path = strings.TrimRight(path, "/") + wantedSuffix
	return u.String()
}

func hasAPIVersionSegment(path string) bool {
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if apiVersionSegmentPattern.MatchString(segment) {
			return true
		}
	}
	return false
}
