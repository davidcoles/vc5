package kernel

import (
	"testing"
)

func viprip(x, y int) (IP4, IP4) {
	vip := natAddress(uint16(x), IP4{192, 168, 0, 0})
	rip := natAddress(uint16(y), IP4{10, 255, 0, 0})
	return vip, rip
}

func TestNAT(t *testing.T) {

	tuples := map[[2]IP4]bool{}

	for x := 0; x < 250; x++ {
		for y := 0; y < 260; y++ {
			vip, rip := viprip(x, y)
			tuples[[2]IP4{vip, rip}] = true
		}
	}

	natmap1 := natIndex(tuples, nil)

	if len(natmap1) != 65000 {
		t.Error("natmap1 != 65000 ", len(natmap1))
	}

	vip, rip := viprip(261, 261)
	tuples[[2]IP4{vip, rip}] = true

	natmap2 := natIndex(tuples, natmap1)

	if len(natmap2) != 65000 {
		t.Error("natmap2 != 65000 ", len(natmap2))
	}

	for k, v := range natmap1 {
		if x, exists := natmap2[k]; !exists {
			t.Error("!exists", k, v)
		} else {
			if x != v {
				t.Error("x != v", k, v, x)
			}
		}
	}

	if _, ok := natmap2[[2]IP4{vip, rip}]; ok {
		t.Error(vip, rip)
	}

	vip, rip = viprip(0, 0)

	old, _ := natmap2[[2]IP4{vip, rip}]

	delete(tuples, [2]IP4{vip, rip})

	natmap3 := natIndex(tuples, natmap2)

	if len(natmap3) != 65000 {
		t.Error("natmap3 != 65000 ", len(natmap3))
	}

	if _, ok := natmap3[[2]IP4{vip, rip}]; ok {
		t.Error(vip, rip)
	}

	vip, rip = viprip(261, 261)

	if v, ok := natmap3[[2]IP4{vip, rip}]; !ok {
		t.Error(vip, rip)
	} else {
		if v != old {
			t.Error(vip, rip, "!= 1", v, old)
		}
	}

	vip, rip = viprip(10, 10)

	delete(tuples, [2]IP4{vip, rip})

	natmap4 := natIndex(tuples, natmap3)

	if len(natmap4) != 64999 {
		t.Error("natmap4 != 64999 ", len(natmap4))
	}

}
