package agent

import "testing"

func TestMissingAuthPrerequisiteGuardBlocksCredentialCracking(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.AuthContextKnown = true
	a.state.AuthContextAvailable = false

	for _, command := range []string{
		`python3 -c "import hashlib; hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 10000)"`,
		`pip install bcrypt && python3 tmp/crack.py`,
		`hashcat -m 10900 hashes.txt wordlist.txt`,
	} {
		blocked, reason := a.shouldBlockForMissingAuthPrerequisites("terminal_execute", map[string]string{"command": command})
		if !blocked || reason == "" {
			t.Fatalf("cracking tool was not blocked: %q (reason=%q)", command, reason)
		}
	}
}

func TestMissingAuthPrerequisiteGuardAllowsAnonymousProbesAndHashEvidence(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.AuthContextKnown = true
	a.state.AuthContextAvailable = false

	for _, command := range []string{
		`curl -sk https://example.test/api/health`,
		`sqlite3 tmp/leaked.db "select login, password, salt from user"`,
		`curl -X POST https://example.test/login -d '{"user":"xalgorix-invalid","password":"canary-8d22"}'`,
		`curl -u admin:admin https://example.test/api/user`,
		`curl -X POST https://example.test/login -d '{"user":"admin","password":"admin"}'`,
	} {
		if blocked, reason := a.shouldBlockForMissingAuthPrerequisites("terminal_execute", map[string]string{"command": command}); blocked {
			t.Fatalf("safe anonymous/evidence command was blocked: %q (%s)", command, reason)
		}
	}
}

func TestMissingAuthPrerequisiteGuardLiftsWithOperatorSession(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.AuthContextKnown = true
	a.state.AuthContextAvailable = true

	if blocked, reason := a.shouldBlockForMissingAuthPrerequisites("terminal_execute", map[string]string{
		"command": `curl -u admin:admin https://example.test/api/user`,
	}); blocked {
		t.Fatalf("operator-authenticated scan was blocked: %s", reason)
	}
}
