package terminal

import (
	"regexp"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// scanHeaderTools are the bundled tools that accept a repeatable
// -H "Name: value" flag with the same semantics as the agent's HTTP client, so
// an operator-configured scan/attribution header can be passed straight
// through. Both httpx and nuclei document -H / -header for exactly this.
var scanHeaderTools = []string{"httpx", "nuclei"}

// InjectScanHeadersIntoCommand appends the operator-configured scan headers
// (XALGORIX_SCAN_HEADERS / -H) as -H "Name: value" flags to every httpx and
// nuclei invocation in command, so bundled-tool traffic carries the same
// identifying header as the agent's own requests. It is pipe-aware (each
// piped stage is handled independently) and idempotent — a header already
// present on a stage is never duplicated. Returns command unchanged when no
// scan headers are configured or no matching tool is invoked.
func InjectScanHeadersIntoCommand(command string) string {
	return injectScanHeaders(command, config.Get().ScanHeaders)
}

// injectScanHeaders is the pure core of InjectScanHeadersIntoCommand, taking
// the header list explicitly so it can be tested without global config.
func injectScanHeaders(command string, headers []string) string {
	if len(headers) == 0 {
		return command
	}
	return rewriteShellSegments(command, func(segment string) string {
		return injectScanHeadersIntoSegment(segment, headers)
	})
}

// injectScanHeadersIntoSegment appends -H flags for a single piped stage when
// that stage invokes a scan-header-aware tool (httpx / nuclei). A stage that
// invokes no such tool is returned unchanged.
func injectScanHeadersIntoSegment(segment string, headers []string) string {
	invokesTool := false
	for _, tool := range scanHeaderTools {
		if hasToolCommand(segment, tool) {
			invokesTool = true
			break
		}
	}
	if !invokesTool {
		return segment
	}
	for _, h := range headers {
		if segmentHasHeader(segment, h) {
			continue
		}
		segment = appendCommandArg(segment, "-H "+shellQuote(h))
	}
	return segment
}

// segmentHasHeader reports whether segment already passes a -H / -header /
// --header flag for the same header name (case-insensitive), so an
// operator-configured header the agent happened to add itself is not
// duplicated.
func segmentHasHeader(segment, header string) bool {
	idx := strings.IndexByte(header, ':')
	if idx <= 0 {
		return false
	}
	name := strings.TrimSpace(header[:idx])
	if name == "" {
		return false
	}
	re := regexp.MustCompile(`(?i)(?:^|\s)-{1,2}(?:h|header)[=\s]+['"]?` + regexp.QuoteMeta(name) + `\s*:`)
	return re.MatchString(segment)
}
