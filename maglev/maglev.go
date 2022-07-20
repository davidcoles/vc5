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

/*
 * http://research.google.com/pubs/pub44824.html
 * https://www.usenix.org/sites/default/files/conference/protected-files/nsdi16_slides_eisenbud.pdf
 */

package maglev

import (
	"crypto/md5"
	"sort"
)

func Maglev65536(nodes [][]byte) (t [65536]uint64) {
	r := maglev(65537, nodes)
	copy(t[:], r[:])

	return
}

func maglev(prime uint64, nodes [][]byte) (table []uint64) {
	offset := make([]uint64, len(nodes))
	skip := make([]uint64, len(nodes))
	table = make([]uint64, prime)

	for n, node := range nodes {
		h := md5.Sum(node)
		hi := (uint64(h[0]) << 24) | (uint64(h[1]) << 16) | (uint64(h[2]) << 8) | (uint64(h[3]))
		lo := (uint64(h[4]) << 24) | (uint64(h[5]) << 16) | (uint64(h[6]) << 8) | (uint64(h[7]))
		offset[n] = hi % prime
		skip[n] = lo%(prime-1) + 1
	}

	current := make([]uint64, len(nodes))
	copy(current[:], offset[:])

	entry := map[uint64]uint64{}

	defer func() {
		for k, v := range entry {
			table[k] = v
		}
	}()

	for {
		for i, c := range current {

		skip:
			if _, ok := entry[c]; ok {
				c = (c + skip[i]) % prime
				current[i] = c
				goto skip
			}

			entry[c] = uint64(i)

			if uint64(len(entry)) == prime {
				return
			}
		}
	}
}

func IPs(nodes map[[4]byte][6]byte) (r [65536][4]byte) {
	if len(nodes) == 0 {
		return
	}

	var n IP4s

	for k, _ := range nodes {
		n = append(n, k)
	}

	sort.Sort(n)

	t := maglev4(65537, n)

	for k, v := range t {
		if k < 65536 {
			r[k] = n[v]
		}
	}

	return
}

func maglev4(prime uint64, nodes []IP4) (table []uint64) {
	if len(nodes) == 0 {
		return
	}

	offset := make([]uint64, len(nodes))
	skip := make([]uint64, len(nodes))
	table = make([]uint64, prime)

	for n, node := range nodes {
		h := md5.Sum(node[:])
		hi := (uint64(h[0]) << 24) | (uint64(h[1]) << 16) | (uint64(h[2]) << 8) | (uint64(h[3]))
		lo := (uint64(h[4]) << 24) | (uint64(h[5]) << 16) | (uint64(h[6]) << 8) | (uint64(h[7]))
		offset[n] = hi % prime
		skip[n] = lo%(prime-1) + 1
	}

	current := make([]uint64, len(nodes))
	copy(current[:], offset[:])

	entry := map[uint64]uint64{}

	defer func() {
		for k, v := range entry {
			table[k] = v
		}
	}()

	for {
		for i, c := range current {

		skip:
			if _, ok := entry[c]; ok {
				c = (c + skip[i]) % prime
				current[i] = c
				goto skip
			}

			entry[c] = uint64(i)

			if uint64(len(entry)) == prime {
				return
			}
		}
	}
}

type IP4 [4]byte
type IP4s []IP4

func (h IP4s) Len() int           { return len(h) }
func (h IP4s) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h IP4s) Less(i, j int) bool { return cmpip4(h[i], h[j]) == -1 }

func cmpip4(a, b [4]byte) int {
	for n := 0; n < len(a); n++ {
		if a[n] < b[n] {
			return -1
		}
		if a[n] > b[n] {
			return 1
		}
	}
	return 0
}
