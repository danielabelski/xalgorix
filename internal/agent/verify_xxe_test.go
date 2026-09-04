package agent

import "testing"

// TestXxeLeakVerdict covers the decision logic of the XXE confirmer without any
// HTTP: the caller supplies the baseline and external-entity probe bodies.
func TestXxeLeakVerdict(t *testing.T) {
	const passwd = "imported 1 record: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
	const benign = "imported 0 records"
	const echoed = "imported 1 record: &xxe;" // entities disabled: literal entity echoed, no file

	tests := []struct {
		name          string
		baseline      string
		probe         string
		wantConfirmed bool
	}{
		{
			// Classic in-band XXE: the passwd content appears only on the payload.
			name: "leak on payload only", baseline: benign, probe: passwd, wantConfirmed: true,
		},
		{
			// External entities disabled (safe): the literal entity is echoed, no file content.
			name: "entities disabled — literal echo", baseline: benign, probe: echoed, wantConfirmed: false,
		},
		{
			// The payload returns nothing recognizable → not confirmed.
			name: "no leak", baseline: benign, probe: benign, wantConfirmed: false,
		},
		{
			// The baseline ALREADY shows passwd markers → not controlled by the entity.
			name: "baseline already leaks", baseline: passwd, probe: passwd, wantConfirmed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confirmed, note := xxeLeakVerdict(tt.baseline, tt.probe, "/etc/passwd")
			if confirmed != tt.wantConfirmed {
				t.Fatalf("confirmed=%v want %v (note=%s)", confirmed, tt.wantConfirmed, note)
			}
			if note == "" {
				t.Error("expected a non-empty explanation note")
			}
		})
	}
}

func TestLooksLikeFileLeak(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{"root:x:0:0:root:/root:/bin/bash", true},
		{"nobody:*:65534:65534:Unprivileged User:/var/empty:/usr/bin/false", true}, // passwd shape
		{"imported 0 records", false},
		{"<data>&xxe;</data>", false},
		{"hello world, no passwd here", false},
	}
	for _, c := range cases {
		if got := looksLikeFileLeak(c.body, "/etc/passwd"); got != c.want {
			t.Errorf("looksLikeFileLeak(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}
