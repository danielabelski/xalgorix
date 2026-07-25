package terminal

import "testing"

func TestInjectScanHeaders(t *testing.T) {
	one := []string{"X-Bug-Bounty: ulises2k"}
	two := []string{"X-Bug-Bounty: ulises2k", "X-Scan-ID: e-42"}
	tests := []struct {
		name    string
		cmd     string
		headers []string
		want    string
	}{
		{
			name:    "no headers configured is a no-op",
			cmd:     "httpx -silent -u https://t.com",
			headers: nil,
			want:    "httpx -silent -u https://t.com",
		},
		{
			name:    "httpx gets the header",
			cmd:     "httpx -silent -u https://t.com",
			headers: one,
			want:    "httpx -silent -u https://t.com -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "nuclei gets the header",
			cmd:     "nuclei -u https://t.com -severity high",
			headers: one,
			want:    "nuclei -u https://t.com -severity high -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "non-target tool is untouched",
			cmd:     "curl -s https://t.com",
			headers: one,
			want:    "curl -s https://t.com",
		},
		{
			name:    "only the httpx stage of a pipe is rewritten",
			cmd:     "cat subs.txt | httpx -silent -status-code",
			headers: one,
			want:    "cat subs.txt | httpx -silent -status-code -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "multiple headers each get a -H",
			cmd:     "httpx -u https://t.com",
			headers: two,
			want:    "httpx -u https://t.com -H 'X-Bug-Bounty: ulises2k' -H 'X-Scan-ID: e-42'",
		},
		{
			name:    "an already-present header is not duplicated",
			cmd:     `httpx -u https://t.com -H "X-Bug-Bounty: someoneelse"`,
			headers: one,
			want:    `httpx -u https://t.com -H "X-Bug-Bounty: someoneelse"`,
		},
		{
			name:    "both httpx and nuclei stages are rewritten",
			cmd:     "httpx -silent | nuclei -silent",
			headers: one,
			want:    "httpx -silent -H 'X-Bug-Bounty: ulises2k' | nuclei -silent -H 'X-Bug-Bounty: ulises2k'",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := injectScanHeaders(tc.cmd, tc.headers)
			if got != tc.want {
				t.Fatalf("injectScanHeaders(%q) =\n  %q\nwant\n  %q", tc.cmd, got, tc.want)
			}
		})
	}
}
