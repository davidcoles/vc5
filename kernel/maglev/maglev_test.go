package maglev

import (
	"fmt"
	"testing"
)

func isEvenlyDistributed(h []uint64, P int) (string, bool) {
	m := map[uint64]int{}

	for _, v := range h {
		m[v]++
	}

	min := -1
	max := 0

	for _, v := range m {
		if min < 0 || v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	if min < 1 {
		return fmt.Sprintf("min %d < 1", min), false
	}

	if max < min {
		return fmt.Sprintf("max %d < min %d", max, min), false
	}

	p := (100 * (max - min)) / min

	if p >= P {
		return fmt.Sprintf("min %d / max %d (%d%%)", min, max, p), false
	}

	return "", true
}

func isSimilar(x int, a, b [][4]byte) (string, bool) {
	multiplier := 2.0

	if x < 32 {
		multiplier = 1.5
	}

	if x < 16 {
		multiplier = 1.2
	}

	if len(a) != len(b) {
		return fmt.Sprintf("%d != %d", len(a), len(b)), false
	}

	d := 0

	for k, v := range a {
		if b[k] != v {
			d++
		}
	}

	D := multiplier * float64(len(a)) / float64(x)

	if float64(d) > D {
		return fmt.Sprintf("%d: %d > %d", x, d, int(D)), false
	}

	return "", true
}

func TestMaglev(t *testing.T) {
	p := 3  // most common entry in table may be mo mode than p% of the least common
	m := 64 // maximum number of nodes to test for

	for x := 4; x < (m - 1); x++ { // -1 becase an extra node is added

		var nodes [][]byte

		for n := 0; n < x; n++ {
			nodes = append(nodes, []byte{10, 1, 2, byte(n)})
		}

		t0 := Maglev8192(nodes)

		if s, ok := isEvenlyDistributed(t0[:], p); !ok {
			t.Error(s)
		}

		var a [][4]byte
		for _, v := range t0 {
			x := nodes[v]
			a = append(a, [4]byte{x[0], x[1], x[2], x[3]})
		}

		nodes = append(nodes, []byte{10, 1, 2, byte(x)})

		t1 := Maglev8192(nodes)

		if s, ok := isEvenlyDistributed(t1[:], p); !ok {
			t.Error(s)
		}

		var b [][4]byte
		for _, v := range t1 {
			x := nodes[v]
			b = append(b, [4]byte{x[0], x[1], x[2], x[3]})
		}

		if s, ok := isSimilar(x, a[:], b[:]); !ok {
			t.Error(s)
		}

		if true {
			nodes = nodes[1:]

			t2 := Maglev8192(nodes)

			if s, ok := isEvenlyDistributed(t2[:], p); !ok {
				t.Error(s)
			}

			var c [][4]byte
			for _, v := range t2 {
				x := nodes[v]
				c = append(c, [4]byte{x[0], x[1], x[2], x[3]})
			}

			if s, ok := isSimilar(x, b[:], c[:]); !ok {
				t.Error(s)
			}
		}
	}
}
