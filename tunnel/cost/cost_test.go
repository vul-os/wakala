package cost

import (
	"math"
	"testing"
)

// close reports whether two euro figures agree to sub-cent precision (float slack).
func close(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestProjectEUR_KnownVolumes pins the €1/TB Hetzner data-plane arithmetic against
// hand-computed volumes, so the "cost-managed" claim is grounded in a checked table
// rather than an assertion made once in prose.
func TestProjectEUR_KnownVolumes(t *testing.T) {
	cases := []struct {
		name     string
		bytes    int64
		eurPerTB float64
		wantEUR  float64
	}{
		{"exactly 1 TB @ Hetzner", BytesPerTB, HetznerEUEURPerTB, 1.0},
		{"10 TB @ Hetzner", 10 * BytesPerTB, HetznerEUEURPerTB, 10.0},
		{"1 GB @ Hetzner", 1_000_000_000, HetznerEUEURPerTB, 0.001},
		{"500 GB @ Hetzner", 500_000_000_000, HetznerEUEURPerTB, 0.5},
		{"1 TB @ Fly Africa (~100x)", BytesPerTB, FlyAfricaEURPerTB, 110.0},
		{"zero bytes", 0, HetznerEUEURPerTB, 0},
		{"negative bytes clamp", -1, HetznerEUEURPerTB, 0},
		{"unpriced region clamp", BytesPerTB, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ProjectEUR(c.bytes, c.eurPerTB)
			if !close(got, c.wantEUR) {
				t.Fatalf("ProjectEUR(%d, %v) = %v, want %v", c.bytes, c.eurPerTB, got, c.wantEUR)
			}
		})
	}
}

// TestProjectEUR_IsLinear proves cost scales linearly with volume — doubling the bytes
// exactly doubles the projection — which is the property that makes per-TB pricing a
// faithful model of a bandwidth-bound relay.
func TestProjectEUR_IsLinear(t *testing.T) {
	base := ProjectEUR(250_000_000_000, HetznerEUEURPerTB) // 250 GB
	doubled := ProjectEUR(500_000_000_000, HetznerEUEURPerTB)
	if !close(doubled, 2*base) {
		t.Fatalf("cost not linear: 250GB=%v, 500GB=%v (want 2x)", base, doubled)
	}
}

// TestTBFor_InvertsProjectEUR: the capacity-planning inverse round-trips.
func TestTBFor_InvertsProjectEUR(t *testing.T) {
	// A €5/mo bandwidth budget at Hetzner EU covers 5 TB; relaying 5 TB costs €5.
	if tb := TBFor(5.0, HetznerEUEURPerTB); !close(tb, 5.0) {
		t.Fatalf("TBFor(5, 1/TB) = %v TB, want 5", tb)
	}
	if eur := ProjectEUR(5*BytesPerTB, HetznerEUEURPerTB); !close(eur, 5.0) {
		t.Fatalf("ProjectEUR(5TB) = %v, want 5", eur)
	}
	// Degenerate inputs project zero capacity.
	if TBFor(0, HetznerEUEURPerTB) != 0 || TBFor(5, 0) != 0 {
		t.Fatal("TBFor should clamp non-positive inputs to 0")
	}
}
