/*
 * VC5 load balancer. Copyright (C) 2021-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package bgp

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
