package realbench

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxHealthBodyBytes = 1 << 20

// PreflightResult records the cheap, deterministic check made before an
// expensive model-backed benchmark run. The manifest can fingerprint the
// expected product version in the health response so accidentally pointing a
// vulnerable run at its patched control (or vice versa) fails closed.
type PreflightResult struct {
	URL        string
	StatusCode int
}

// PreflightTarget verifies that the selected loopback target is healthy and,
// when configured, that its response matches the manifest fingerprint. It does
// not follow redirects: a login redirect or a different origin is not proof
// that the intended benchmark container is ready.
func PreflightTarget(ctx context.Context, target Target, targetURL string) (PreflightResult, error) {
	if err := ValidateLoopbackURL(targetURL); err != nil {
		return PreflightResult{}, err
	}
	path := strings.TrimSpace(target.Container.HealthPath)
	if path == "" {
		return PreflightResult{}, nil
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("parse target URL: %w", err)
	}
	reference, err := url.Parse(path)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("parse health path: %w", err)
	}
	healthURL := base.ResolveReference(reference)
	if !strings.EqualFold(healthURL.Scheme, base.Scheme) || !strings.EqualFold(healthURL.Host, base.Host) {
		return PreflightResult{}, fmt.Errorf("health check escaped the target origin")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL.String(), nil)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("build health request: %w", err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("GET %s: %w", healthURL, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHealthBodyBytes+1))
	if err != nil {
		return PreflightResult{}, fmt.Errorf("read %s: %w", healthURL, err)
	}
	result := PreflightResult{URL: healthURL.String(), StatusCode: response.StatusCode}
	if len(body) > maxHealthBodyBytes {
		return result, fmt.Errorf("GET %s returned a health body larger than %d bytes", healthURL, maxHealthBodyBytes)
	}
	expectedStatus := target.Container.HealthStatus
	if expectedStatus == 0 {
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return result, fmt.Errorf("GET %s returned HTTP %d; expected 2xx", healthURL, response.StatusCode)
		}
	} else if response.StatusCode != expectedStatus {
		return result, fmt.Errorf("GET %s returned HTTP %d; expected %d", healthURL, response.StatusCode, expectedStatus)
	}
	if pattern := strings.TrimSpace(target.Container.HealthBodyRegexp); pattern != "" {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return result, fmt.Errorf("invalid health body regexp: %w", err)
		}
		if !compiled.Match(body) {
			return result, fmt.Errorf("GET %s did not match the expected product/version fingerprint", healthURL)
		}
	}
	return result, nil
}
