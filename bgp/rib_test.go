package bgp4

import (
	"testing"
)

func TestRIBs(t *testing.T) {
	a := IP{192, 168, 101, 1}
	b := IP{192, 168, 101, 2}

	type test struct {
		x []IP
		y []IP
		e bool
	}

	tests := []test{
		test{[]IP{}, []IP{}, false}, // two empty lists don't differ
		test{[]IP{a}, []IP{}, true},
		test{[]IP{}, []IP{a}, true},
		test{[]IP{a, a}, []IP{a}, false}, // repeated elements are ignored
		test{[]IP{a}, []IP{a, a}, false}, // repeated elements are ignored
		test{[]IP{a}, []IP{b}, true},
	}

	for _, i := range tests {
		r := RIBSDiffer(i.x, i.y)
		if r != i.e {
			t.Fatalf("Expected %v, got %v: %v %v\n", i.e, r, i.x, i.y)
		}
	}
}
