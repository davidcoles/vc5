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

package maglev

import (
	"crypto/sha256"
)

func Maglev65536(nodes [][]byte) (t [65536]uint64) {
	r := Maglev(65537, nodes)
	copy(t[:], r[:])
	return
}

func Maglev8192(nodes [][]byte) (t [8192]uint64) {
	r := Maglev(8209, nodes)
	copy(t[:], r[:])
	return
}

/*
 * http://research.google.com/pubs/pub44824.html
 * https://www.usenix.org/sites/default/files/conference/protected-files/nsdi16_slides_eisenbud.pdf
 */

func Maglev(prime uint64, nodes [][]byte) (table []uint64) {
	offset := make([]uint64, len(nodes))
	skip := make([]uint64, len(nodes))
	table = make([]uint64, prime)

	for n, node := range nodes {
		//h := md5.Sum(node)
		h := sha256.Sum256(node)
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
