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

package kernel

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/davidcoles/vc5/maglev"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/xdp"
)

type be_state struct {
	backend     map[IP4]monitor.Backend
	health      map[IP4]bool
	sticky      bool
	fallback    bool
	leastconns  IP4
	weight      uint8
	bpf_backend bpf_backend
}

func boolint(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func (m *maps) Balancer(c Report) (chan Report, func() map[Target]Counter) {

	var mu sync.Mutex
	type l4Service struct {
		vip IP4
		svc L4
	}

	ch := make(chan Report)

	stats := map[Target]bool{}
	conns := map[Target]uint64{}

	go func() {
		var era bool

		for {
			time.Sleep(10 * time.Second)

			era = !era

			var zero uint32
			set := bpf_setting{defcon: m.defcon, era: boolint(era)}
			if xdp.BpfMapUpdateElem(m.settings(), uP(&zero), uP(&set), xdp.BPF_ANY) != 0 {
				panic("oops")
			}

			s := map[Target]bool{}
			mu.Lock()
			for k, v := range stats {
				s[k] = v
			}
			mu.Unlock()

			c := map[Target]uint64{}

			for v, _ := range s {
				var n int64
				vrrp := bpf_vrpp{vip: v.VIP, rip: v.RIP, port: htons(v.Port), protocol: v.Protocol, pad: boolint(!era)}
				r := m.lookup_vrpp_concurrent(&vrrp, &n)
				fmt.Println("XXXXXXXXXXXXXXXXX", boolint(era), r, v, n)
				m.update_vrpp_concurrent(&vrrp, nil, xdp.BPF_EXIST)

				if n > 0 {
					c[v] = uint64(n)
				}
			}

			mu.Lock()
			conns = c
			mu.Unlock()
		}
	}()

	get_stats := func() map[Target]Counter {
		r := map[Target]Counter{}
		s := map[Target]bool{}
		c := map[Target]uint64{}

		mu.Lock()
		for k, v := range stats {
			s[k] = v
		}
		for k, v := range conns {
			c[k] = v
		}
		mu.Unlock()

		for v, _ := range s {
			var b bpf_counter
			vrrp := bpf_vrpp{vip: v.VIP, rip: v.RIP, port: htons(v.Port), protocol: v.Protocol}
			m.lookup_vrpp_counter(&vrrp, &b)
			r[v] = Counter{Octets: b.octets, Packets: b.packets, Concurrent: c[v]}
		}

		return r
	}

	go func() {
		state := map[l4Service]*be_state{}
		vips := map[IP4]bool{}

		for config := range ch {

			if false {
				js, err := json.MarshalIndent(&config, "", "  ")
				fmt.Println(string(js), err)
			}

			inUse := map[l4Service]bool{}

			for vip, virtual := range config.Virtuals {

				vr := bpf_vrpp{vip: vip} // all oher fields 0
				m.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
				vips[vip] = true

				for l4, s := range virtual.Services {

					fmt.Println(vip, l4, s)

					l4service := l4Service{vip: vip, svc: l4}

					inUse[l4service] = true

					// update what stats we should harvest
					for ip, _ := range s.Health {
						if be, ok := config.Backends[ip]; ok {
							vr := bpf_vrpp{vip: vip, rip: be.IP, port: htons(l4.Port), protocol: l4.Protocol.Number()}
							m.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
							m.update_vrpp_concurrent(&vr, nil, xdp.BPF_NOEXIST)
							vr.pad = 1
							m.update_vrpp_concurrent(&vr, nil, xdp.BPF_NOEXIST)
							b := Target{VIP: vip, RIP: be.IP, Port: l4.Port, Protocol: l4.Protocol.Number()}
							mu.Lock()
							stats[b] = true
							mu.Unlock()
						}
					}

					key := &bpf_service{vip: vip, port: l4.NP(), protocol: l4.PN()}
					val := &be_state{fallback: s.Fallback, sticky: s.Sticky, leastconns: s.Leastconns, weight: s.Weight,
						health: s.Health, backend: config.Backends}

					if val.update(state[l4service]) {
						m.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
						state[l4service] = val
					}
				}
			}

			for k, _ := range state {
				if _, ok := inUse[k]; !ok {
					s := bpf_service{vip: k.vip, port: k.svc.NP(), protocol: k.svc.PN()}
					xdp.BpfMapDeleteElem(m.service_backend(), uP(&s))
					delete(state, k)
				}
			}

			for vip, _ := range vips {
				if _, ok := config.Virtuals[vip]; !ok {
					s := bpf_service{vip: vip}
					xdp.BpfMapDeleteElem(m.service_backend(), uP(&s))
				}
				delete(vips, vip)
			}

			fmt.Println("======================================================================")
		}
	}()

	ch <- c
	return ch, get_stats
}

func maglev8192(m map[[4]byte]uint8) (r [8192]uint8, b bool) {

	if len(m) < 1 {
		return r, false
	}

	a := IP4s(make([]IP4, len(m)))

	n := 0
	for k, _ := range m {
		a[n] = k
		n++
	}

	sort.Sort(a)

	h := make([][]byte, len(a))

	for k, v := range a {
		b := make([]byte, 4)
		copy(b[:], v[:])
		h[k] = b
	}

	t := maglev.Maglev8192(h)

	for k, v := range t {
		ip := a[v]
		x, ok := m[ip]
		if !ok {
			return r, false
		}
		r[k] = x
	}

	return r, true
}

func (curr *be_state) update(prev *be_state) bool {

	if prev != nil {

		if curr.sticky != prev.sticky ||
			curr.fallback != prev.fallback ||
			curr.leastconns != prev.leastconns ||
			curr.weight != prev.weight {
			goto build
		}

		/**********************************************************************/
		for k, v := range curr.backend {
			if x, ok := prev.backend[k]; !ok || x != v {
				goto build
			}
		}

		for k, v := range prev.backend {
			if x, ok := curr.backend[k]; !ok || x != v {
				goto build
			}
		}

		for k, v := range curr.health {
			if x, ok := prev.health[k]; !ok || x != v {
				goto build
			}
		}

		for k, v := range prev.health {
			if x, ok := curr.health[k]; !ok || x != v {
				goto build
			}
		}
		/**********************************************************************/
		return false
	}

build:
	var flag [4]byte

	const F_STICKY = 0x01
	const F_FALLBACK = 0x02

	if curr.sticky {
		flag[0] |= F_STICKY
	}

	if curr.fallback {
		flag[0] |= F_FALLBACK
	}

	m := map[[4]byte]uint8{}

	now := time.Now()

	for k, v := range curr.health {
		if b, ok := curr.backend[k]; ok && v {
			m[b.IP] = uint8(b.Idx)
		}
	}

	curr.bpf_backend.hash, _ = maglev8192(m)

	for _, b := range curr.backend {
		curr.bpf_backend.real[b.Idx] = bpf_real{rip: b.IP, mac: b.MAC, vid: htons(b.VID)}
	}

	var rip IP4
	var mac MAC
	var vid uint16

	var nilip IP4
	if curr.leastconns != nilip {
		fmt.Println(curr.leastconns)
		if b, ok := curr.backend[curr.leastconns]; ok {
			flag[1] = curr.weight
			rip = b.IP
			mac = b.MAC
			vid = b.VID
		}

	}

	curr.bpf_backend.real[0] = bpf_real{rip: rip, mac: mac, vid: htons(vid), flag: flag}

	fmt.Println("******** UPDATED", curr.bpf_backend.hash[:32], time.Now().Sub(now))

	return true
}
