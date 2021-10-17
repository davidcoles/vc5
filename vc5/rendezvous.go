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

package main

import (
	"crypto/md5"
	"fmt"
	"sort"
	"time"
)

type Stats struct {
	Variance float32
	Duration time.Duration
}

type hwaddrs [][6]byte

func (h hwaddrs) Len() int           { return len(h) }
func (h hwaddrs) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h hwaddrs) Less(i, j int) bool { return cmpmac(h[i], h[j]) == -1 }

type macrips [][10]byte

func (h macrips) Len() int           { return len(h) }
func (h macrips) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h macrips) Less(i, j int) bool { return cmpmacrip(h[i], h[j]) == -1 }

func cmpmacs(a, b [][6]byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if cmpmac(a[i], b[i]) != 0 {
			return false
		}
	}

	return true
}

func cmpmac(a, b [6]byte) int {
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

func cmpmacrips(a, b [][10]byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if cmpmacrip(a[i], b[i]) != 0 {
			return false
		}
	}

	return true
}

func cmpmacrip(a, b [10]byte) int {
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

func Rendezvous(hws [][6]byte) ([65536][6]byte, Stats) {
	var nodes hwaddrs = hws

	var t [65536][6]byte
	var s Stats

	t1 := time.Now()

	sort.Sort(nodes)

	m := make(map[[6]byte]int)

	for n := 0; n < len(t); n++ {
		a := best(uint16(n), nodes)
		t[n] = a

		if _, ok := m[a]; ok {
			m[a]++
		} else {
			m[a] = 1
		}
	}

	s.Duration = time.Now().Sub(t1)

	min := 0
	max := 0

	if len(m) > 0 {
		d := false
		for _, v := range m {
			if !d {
				d = true
				min = v
			}
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
		}
		s.Variance = float32((max-min)*100) / float32(min)
	}

	//dump(m)

	return t, s
}

func Rendezvous2(hws [][10]byte) ([65536][10]byte, Stats) {
	var nodes macrips = hws

	fmt.Println("!!!!!!!!", nodes)

	var t [65536][10]byte
	var s Stats

	t1 := time.Now()

	sort.Sort(nodes)

	m := make(map[[10]byte]int)

	for n := 0; n < len(t); n++ {
		a := best2(uint16(n), nodes)
		t[n] = a

		if _, ok := m[a]; ok {
			m[a]++
		} else {
			m[a] = 1
		}
	}

	s.Duration = time.Now().Sub(t1)

	min := 0
	max := 0

	if len(m) > 0 {
		d := false
		for _, v := range m {
			if !d {
				d = true
				min = v
			}
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
		}
		s.Variance = float32((max-min)*100) / float32(min)
	}

	//dump(m)

	return t, s
}

func dump(m map[[6]byte]int) {
	for _, v := range m {
		fmt.Print(v, " ")
	}
	fmt.Println("")
}

func best2(key uint16, nodes [][10]byte) [10]byte {
	var best [10]byte
	var high uint32

	for _, n := range nodes {
		var data [12]byte
		data[0] = byte(key >> 8)
		data[1] = byte(key & 0xff)
		copy(data[2:], n[:])

		h := md5.Sum(data[:])
		s := (uint32(h[0]) << 24) | (uint32(h[1]) << 16) | (uint32(h[2]) << 8) | (uint32(h[3]))

		if s >= high {
			high = s
			best = n
		}
	}

	return best
}

func best(key uint16, nodes [][6]byte) [6]byte {
	var best [6]byte
	var high uint32

	for _, n := range nodes {
		var data [8]byte
		data[0] = byte(key >> 8)
		data[1] = byte(key & 0xff)
		copy(data[2:], n[:])

		// maybe look at http://cyan4973.github.io/xxHash/
		// djb2, sdbm, crc32, etc do not distribute evenly enough
		// md5 is "fast enough" for < 50 nodes (50: <1s, 20: <0.4s)
		h := md5.Sum(data[:])
		s := (uint32(h[0]) << 24) | (uint32(h[1]) << 16) | (uint32(h[2]) << 8) | (uint32(h[3]))

		if s >= high {
			high = s
			best = n
		}
	}

	return best
}
