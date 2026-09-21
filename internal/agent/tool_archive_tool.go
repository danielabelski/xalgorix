package agent

import (
	"fmt"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// registerToolArchiveTool registers read_tool_output — the retrieval side of
// bounded working context. Aged tool-result messages are replaced by stubs
// naming an archive id; this tool returns the byte-identical complete original
// from <ScanDir>/tool-outputs/<id> so no information is ever lost, only
// fetched lazily instead of being resent on every iteration.
func (a *Agent) registerToolArchiveTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "read_tool_output",
		Description: "Retrieve the COMPLETE original output of an earlier tool result that was archived to keep the working context small. The stub message in the conversation names the archive id. Use this whenever you need the full untruncated output referenced by a stub (ids look like to_000042). The original file is also readable directly at tool-outputs/<id> inside the scan workdir via terminal tools.",
		Parameters: []tools.Parameter{
			{Name: "id", Description: "Archive id of the tool output (e.g. to_000042), as shown in the archived stub message.", Required: true},
		},
		Execute: a.readToolOutputTool,
	})
}

func (a *Agent) readToolOutputTool(args map[string]string) (tools.Result, error) {
	id := strings.TrimSpace(args["id"])
	if id == "" {
		return tools.Result{Error: "id is required — it appears in the archived stub message, e.g. read_tool_output(id=\"to_000042\")"}, nil
	}
	if a.scanCtx == nil || a.scanCtx.ToolOutputs == nil {
		return tools.Result{Error: "tool-output archive unavailable in this context"}, nil
	}
	content, ok := a.scanCtx.ToolOutputs.Get(id)
	if !ok {
		return tools.Result{Error: fmt.Sprintf("no archived tool output with id %q — the id appears in the stub message of the archived result", id)}, nil
	}
	// The in-conversation view goes through the same per-message cap as every
	// other tool result (head+tail). The archived file keeps the complete
	// byte-identical original on disk.
	return tools.Result{Output: content}, nil
}
