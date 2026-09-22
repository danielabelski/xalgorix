package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func TestVerifierPromptPreservesRawTraversalPaths(t *testing.T) {
	prompt := buildVerifierPrompt(reporting.VerificationRequest{
		Title: "Path traversal in plugin assets", CWE: "CWE-22",
		Endpoint: "http://target.test/public/plugins/input/../../etc/passwd",
	}, "<tool name=\"verify_path_traversal\" />")
	for _, want := range []string{
		"verify_path_traversal", "use --path-as-is --globoff",
		"client-normalized request is NOT positive disproof",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("independent verifier prompt omitted %q", want)
		}
	}
}
