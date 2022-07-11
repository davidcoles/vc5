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
	//"crypto/sha256"
	"sort"
	"time"
)

type Stats struct {
	Variance float32
	Duration time.Duration
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

func RipIndex(ips map[[4]byte]uint16) ([8192]uint8, Stats) {
	var r [8192]uint8
	a, s := _RipIndex(ips, 8192)
	copy(r[:], a[:])
	return r, s
}

func _RipIndex(ips map[[4]byte]uint16, n uint) ([]uint8, Stats) {

	var s Stats
	//var t [8192]uint8
	t := make([]uint8, n)

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
		if ips[a] == 0 || ips[a] > 255 {
			panic("Backend out of range")
		}
		t[n] = uint8(ips[a])

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
		//h := sha256.Sum256(data[:])
		s := (uint32(h[0]) << 24) | (uint32(h[1]) << 16) | (uint32(h[2]) << 8) | (uint32(h[3]))

		if s >= high {
			high = s
			best = n
		}
	}

	return best

}

// 256 {165 297.539541ms}
// 100 {76.190475 126.545233ms}
// 50 {46.043167 76.358566ms}
// 20 {23.896105 26.480638ms}
func Test(x uint16) ([8192]uint8, Stats) {
	m := map[[4]byte]uint16{}
	for n := uint16(1); n < x; n++ {
		m[[4]byte{10, 255, byte(n >> 8), byte(n & 0xff)}] = n
	}
	return RipIndex(m)
}

func RipIndex64k(ips map[[4]byte]uint16) ([65536]uint8, Stats) {
	var r [65536]uint8
	a, s := _RipIndex(ips, 65536)
	copy(r[:], a[:])
	return r, s
}

// 256 {42.32558 2.332370579s}
// 100 {18.2266 867.378658ms}
// 20 {5.0163255 178.708765ms}
func Test64k(x uint16) ([65536]uint8, Stats) {
	m := map[[4]byte]uint16{}
	for n := uint16(1); n < x; n++ {
		m[[4]byte{10, 255, byte(n >> 8), byte(n & 0xff)}] = n
	}
	return RipIndex64k(m)
}

//fmt.Println(rendezvous.Test(20))
//	return
