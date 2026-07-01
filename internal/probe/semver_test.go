package probe

import "testing"

func TestSemverLess_NumericComponents(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.1.99", "2.1.197", true}, // the exact bug: lexical would say false
		{"2.1.197", "2.1.99", false},
		{"2.1.197", "2.1.197", false}, // equal
		{"1.0.0", "2.0.0", true},
		{"2.1.0", "2.10.0", true},
		{"2.1.197", "2.2.0", true},
	}
	for _, c := range cases {
		if got := semverLess(c.a, c.b); got != c.want {
			t.Errorf("semverLess(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSemverLess_PicksHighestInLoop(t *testing.T) {
	versions := []string{"2.1.99", "2.1.197", "2.1.5", "2.2.0"}
	var best string
	for _, v := range versions {
		if best == "" || semverLess(best, v) {
			best = v
		}
	}
	if best != "2.2.0" {
		t.Fatalf("best = %q, want 2.2.0", best)
	}
}
