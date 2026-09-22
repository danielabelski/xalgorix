package tools

import (
	"sort"
	"strings"
	"testing"
)

func testRegistryWithTools(t *testing.T, names ...string) *Registry {
	t.Helper()
	r := NewRegistry()
	for _, n := range names {
		r.Register(&Tool{
			Name:        n,
			Description: n + " description",
			Parameters:  []Parameter{{Name: "x", Description: "param", Required: true}},
			Execute: func(args map[string]string) (Result, error) {
				return Result{Output: "ran " + n}, nil
			},
		})
	}
	return r
}

func TestSchemaHiddenWithholdsDocsAndKeepsIndex(t *testing.T) {
	r := testRegistryWithTools(t, "terminal_execute", "http_request", "browser_action", "page_agent")

	full := r.SchemaXML()
	for _, want := range []string{"terminal_execute", "http_request", "browser_action", "page_agent"} {
		if !strings.Contains(full, want) {
			t.Fatalf("full schema missing %s", want)
		}
	}

	r.SetSchemaHidden([]string{"browser_action", "page_agent"})
	scoped := r.SchemaXML()
	if strings.Contains(scoped, "browser_action description") {
		t.Fatal("hidden tool description must not appear")
	}
	if strings.Contains(scoped, "page_agent description") {
		t.Fatal("hidden tool description must not appear")
	}
	// Compact one-line index keeps the model aware the tools exist.
	if !strings.Contains(scoped, "<hidden_tools>browser_action, page_agent</hidden_tools>") {
		t.Fatalf("schema missing hidden-tools index: %s", scoped)
	}
	if !strings.Contains(scoped, "terminal_execute") || !strings.Contains(scoped, "http_request") {
		t.Fatal("visible tools must remain fully documented")
	}

	// Clearing restores the full schema.
	r.SetSchemaHidden(nil)
	if r.SchemaXML() != full {
		t.Fatal("clearing the scope must restore the original schema byte-for-byte")
	}
}

func TestSchemaHiddenToolsStayCallable(t *testing.T) {
	r := testRegistryWithTools(t, "http_request", "browser_action")
	r.SetSchemaHidden([]string{"browser_action"})

	tool, ok := r.Get("browser_action")
	if !ok || tool.Name != "browser_action" {
		t.Fatal("hidden tool must stay registered")
	}
	out, err := tool.Execute(map[string]string{"x": "1"})
	if err != nil || out.Output != "ran browser_action" {
		t.Fatalf("hidden tool must stay executable: %v %+v", err, out)
	}
}

func TestSchemaHiddenNamesSorted(t *testing.T) {
	r := testRegistryWithTools(t, "a", "b", "c")
	r.SetSchemaHidden([]string{"c", "a"})
	got := r.SchemaHiddenNames()
	if !sort.StringsAreSorted(got) || got[0] != "a" || got[1] != "c" {
		t.Fatalf("SchemaHiddenNames = %v", got)
	}
}

func TestRequiresParamsAndListUnaffectedByHiding(t *testing.T) {
	r := testRegistryWithTools(t, "http_request", "browser_action")
	r.SetSchemaHidden([]string{"browser_action"})
	if !r.RequiresParams("browser_action") {
		t.Fatal("hidden tool parameter requirements must keep working")
	}
	found := false
	for _, n := range r.List() {
		if n == "browser_action" {
			found = true
		}
	}
	if !found {
		t.Fatal("List must still enumerate hidden tools (they are callable)")
	}
}
