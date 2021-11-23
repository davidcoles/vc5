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

package rendezvous

import (
	"crypto/md5"
	"fmt"
	"sort"
	"time"
	//"github.com/dchest/siphash"
)

type Stats struct {
	Variance float32
	Duration time.Duration
}

type B12s [][12]byte

func (h B12s) Len() int           { return len(h) }
func (h B12s) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h B12s) Less(i, j int) bool { return cmpb12(h[i], h[j]) == -1 }

func cmpB12s(a, b [][12]byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if cmpb12(a[i], b[i]) != 0 {
			return false
		}
	}

	return true
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

func RipIndex(ips map[[4]byte]uint8) ([8192]uint8, Stats) {

	var s Stats
	var t [8192]uint8

	if len(ips) < 1 {
		return t, s
	}

	var list IP4s

	for r, _ := range ips {
		list = append(list, r)
	}

	sort.Sort(list)

	t1 := time.Now()

	m := make(map[[4]byte]int)

	for n := 0; n < len(t); n++ {
		a := high(uint16(n), list)
		t[n] = ips[a]

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

	return t, s
}

func high(key uint16, nodes []IP4) IP4 {
	var best IP4
	var high uint32

	for _, n := range nodes {
		var data [6]byte
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

func cmpb12(a, b [12]byte) int {
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

func Rendezvous(hws [][12]byte) ([65536][12]byte, Stats) {
	var nodes B12s = hws

	var t [65536][12]byte
	var s Stats

	if len(nodes) < 1 {
		return t, s
	}

	t1 := time.Now()

	sort.Sort(nodes)

	m := make(map[[12]byte]int)

	for n := 0; n < len(t); n++ {
		a := best3(uint16(n), nodes)
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

func best3(key uint16, nodes [][12]byte) [12]byte {
	var best [12]byte
	var high uint32

	for _, n := range nodes {
		var data [14]byte
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

func bestsh(key uint16, nodes [][12]byte) [12]byte {
	var best [12]byte
	var high uint64

	for _, n := range nodes {
		var data [14]byte
		data[0] = byte(key >> 8)
		data[1] = byte(key & 0xff)
		copy(data[2:], n[:])

		//h := md5.Sum(data[:])

		var key0 uint64
		var key1 uint64

		//s := siphash.Hash(key0, key1, data[:])
		s := key0 + key1

		if s >= high {
			high = s
			best = n
		}
	}

	return best
}
