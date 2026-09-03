package agent

import "testing"

// TestSstiEvalVerdict covers the decision logic of the SSTI confirmer without
// any HTTP: the caller supplies the baseline and probe bodies plus the expected
// product of the injected arithmetic expression.
func TestSstiEvalVerdict(t *testing.T) {
	const product = "56088" // e.g. 123*456

	tests := []struct {
		name          string
		baseline      string
		probe         string
		product       string
		wantConfirmed bool
	}{
		{
			// Engine evaluated {{123*456}} to 56088; baseline (benign) has no product.
			name: "evaluated product only in probe", baseline: "<h1>Hello xalg</h1>",
			probe: "<h1>Hello 56088</h1>", product: product, wantConfirmed: true,
		},
		{
			// Reflected literally: the echo contains the payload, not the product.
			name: "reflected literally not evaluated", baseline: "<h1>Hello xalg</h1>",
			probe: "<h1>Hello {{123*456}}</h1>", product: product, wantConfirmed: false,
		},
		{
			// Product also present in baseline → coincidental, reject.
			name: "product also in baseline", baseline: "order #56088 total",
			probe: "order #56088 total 56088", product: product, wantConfirmed: false,
		},
		{
			// No product to check → reject.
			name: "empty product", baseline: "x", probe: "y", product: "", wantConfirmed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confirmed, note := sstiEvalVerdict(tt.baseline, tt.probe, tt.product)
			if confirmed != tt.wantConfirmed {
				t.Fatalf("confirmed=%v want %v (note=%s)", confirmed, tt.wantConfirmed, note)
			}
			if note == "" {
				t.Errorf("expected a non-empty explanation note")
			}
		})
	}
}

// TestRandRange checks the operand generator stays within [min,max) and handles
// an empty range gracefully.
func TestRandRange(t *testing.T) {
	for i := 0; i < 200; i++ {
		n := randRange(211, 989)
		if n < 211 || n >= 989 {
			t.Fatalf("randRange(211,989)=%d out of range", n)
		}
	}
	if got := randRange(5, 5); got != 5 {
		t.Errorf("empty range should return min, got %d", got)
	}
	if got := randRange(9, 3); got != 9 {
		t.Errorf("inverted range should return min, got %d", got)
	}
}
