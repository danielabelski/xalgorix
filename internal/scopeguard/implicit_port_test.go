package scopeguard

import "testing"

// TestImplicitPortDoesNotBypassDashboardExclusion covers the case where a target
// URL omits an explicit port. url.Port() returns "" there, which previously made
// localTargetsAllowed("") pass unconditionally and skipped the self-listener
// fast-path (gated on hostPort != ""), so IsLocalOrListener returned false
// (not-self) for the dashboard's own listener when it ran on port 80/443.
func TestImplicitPortDoesNotBypassDashboardExclusion(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		target string
		want   bool
	}{
		{
			name:   "https no port, dashboard on 443, loopback bind -> self (blocked)",
			cfg:    Config{Port: 443, AllowLocalTargets: true},
			target: "https://127.0.0.1/",
			want:   true,
		},
		{
			name:   "https no port, dashboard on 443, 0.0.0.0 bind (docker) -> self (blocked)",
			cfg:    Config{BindAddr: "0.0.0.0", Port: 443, AllowLocalTargets: true},
			target: "https://127.0.0.1/",
			want:   true,
		},
		{
			name:   "http no port, dashboard on 80 -> self (blocked)",
			cfg:    Config{Port: 80, AllowLocalTargets: true},
			target: "http://127.0.0.1/",
			want:   true,
		},
		{
			// Regression guard: with the default dashboard port, an implicit
			// :443 does NOT collide with the listener, so a genuinely-local
			// target stays allowed (the point of AllowLocalTargets). The fix
			// must not over-block.
			name:   "https no port, dashboard on 9137 -> allowed local target",
			cfg:    Config{Port: 9137, AllowLocalTargets: true},
			target: "https://127.0.0.1/",
			want:   false,
		},
		{
			name:   "explicit non-dashboard port stays allowed",
			cfg:    Config{Port: 443, AllowLocalTargets: true},
			target: "https://127.0.0.1:8080/",
			want:   false,
		},
		{
			name:   "explicit dashboard port blocked",
			cfg:    Config{Port: 443, AllowLocalTargets: true},
			target: "https://127.0.0.1:443/",
			want:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLocalOrListener(tc.cfg, tc.target); got != tc.want {
				t.Errorf("IsLocalOrListener(%+v, %q) = %v; want %v", tc.cfg, tc.target, got, tc.want)
			}
		})
	}
}

func TestSchemeDefaultPort(t *testing.T) {
	cases := map[string]string{
		"http": "80", "https": "443",
		"HTTP": "80", "HTTPS": "443",
		"ws": "80", "wss": "443",
		"ftp": "", "": "",
	}
	for scheme, want := range cases {
		if got := schemeDefaultPort(scheme); got != want {
			t.Errorf("schemeDefaultPort(%q) = %q; want %q", scheme, got, want)
		}
	}
}
