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
