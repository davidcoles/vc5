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
	"sync"
	"time"

	"github.com/davidcoles/vc5/types"
	"github.com/davidcoles/vc5/xdp"
)

const (
	A = false
	B = true
)

type Counter struct {
	Octets     uint64
	Packets    uint64
	Flows      uint64
	Concurrent uint64
	// globals ...
	Latency uint64
	DEFCON  uint8
}

type Balancer struct {
	maps   *maps
	report chan Report
	stats  func() map[Target]Counter
}

func (b *Balancer) Close() {
	close(b.report)
}

func (b *Balancer) Configure(r Report) {
	b.report <- r
}

func (b *Balancer) Stats() map[Target]Counter {
	return b.stats()
}

func (m *maps) Balancer(c Report, l types.Logger) *Balancer {
	report, stats := m.balancer(c, l)
	return &Balancer{maps: m, report: report, stats: stats}
}

func (b *Balancer) Global() Counter {
	var g bpf_global
	b.maps.lookup_globals(&g)

	var latency uint64
	if g.perf_packets > 0 {
		latency = g.perf_timens / g.perf_packets
	}

	return Counter{Octets: g.rx_octets, Packets: g.rx_packets, Flows: g.new_flows, Latency: latency, DEFCON: b.maps.defcon}
}

func (m *maps) balancer(c Report, l types.Logger) (chan Report, func() map[Target]Counter) {
	FACILITY := "balancer"

	var mu sync.Mutex
	type l4Service struct {
		vip IP4
		svc L4
	}

	ch := make(chan Report)

	stats := map[Target]bool{}       // list of stats to collect - not values!
	conns := map[Target]bpf_active{} // current active connections cache

	done := make(chan bool)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		var era uint8

		for {
			select {
			case <-done:
				return

			case <-ticker.C:

				s := map[Target]bool{}
				c := map[Target]bpf_active{}

				// grab a copy of stats that we're interested in
				mu.Lock()
				for k, v := range stats {
					s[k] = v
				}
				mu.Unlock()

				era++
				old := era%2 == 0

				m.ERA(era) // write back new setting to kernel

				// iterate over the selection reading counters at our leisure
				for v, _ := range s {
					var a bpf_active
					vrrp := bpf_vrpp{vip: v.VIP, rip: v.RIP, port: htons(v.Port), protocol: v.Protocol}
					m.lookup_vrpp_concurrent(old, &vrrp, &a)                 // lookup previous counter
					m.update_vrpp_concurrent(old, &vrrp, nil, xdp.BPF_EXIST) // clear previous counter

					c[v] = a
				}

				// write counters back to the visible copy
				mu.Lock()
				conns = c
				mu.Unlock()
			}
		}
	}()

	get_stats := func() map[Target]Counter {
		// local copies of stats to fil in
		s := map[Target]Counter{}
		c := map[Target]bpf_active{}

		mu.Lock()
		for k, _ := range stats {
			s[k] = Counter{}
		}
		for k, v := range conns {
			c[k] = v
		}
		mu.Unlock()

		for k, _ := range s {
			var b bpf_counter
			vrrp := bpf_vrpp{vip: k.VIP, rip: k.RIP, port: htons(k.Port), protocol: k.Protocol}
			m.lookup_vrpp_counter(&vrrp, &b)
			s[k] = Counter{Octets: b.octets, Packets: b.packets, Flows: b.flows, Concurrent: uint64(c[k].current)}
		}

		return s
	}

	go func() {
		defer close(done)
		state := map[l4Service]*be_state{}
		vips := map[IP4]bool{}

		for report := range ch {

			l.CRIT(FACILITY, "Configuration update")

			if false {
				js, err := json.MarshalIndent(&report, "", "  ")
				fmt.Println(string(js), err)
			}

			services := map[l4Service]bool{}
			targets := map[Target]bool{}

			for vip, virtual := range report.Virtual {

				vr := bpf_vrpp{vip: vip} // all oher fields 0
				m.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
				vips[vip] = true

				for l4, s := range virtual.Services {

					l4service := l4Service{vip: vip, svc: l4}

					services[l4service] = true

					// update what stats we should harvest
					//for ip, _ := range s.Probe {
					for ip, _ := range s.Reals {
						if be, ok := report.Backends[ip]; ok {
							vr := bpf_vrpp{vip: vip, rip: be.IP, port: htons(l4.Port), protocol: l4.Protocol.Number()}
							m.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
							m.update_vrpp_concurrent(A, &vr, nil, xdp.BPF_NOEXIST) // create 'A' counter if it does not exist
							m.update_vrpp_concurrent(B, &vr, nil, xdp.BPF_NOEXIST) // create 'B' counter if it does not exist
							b := Target{VIP: vip, RIP: be.IP, Port: l4.Port, Protocol: l4.Protocol.Number()}
							mu.Lock()
							stats[b] = true
							targets[b] = true
							mu.Unlock()
						}
					}

					health := map[IP4]bool{}
					//for i, p := range s.Probe {
					//	health[i] = p.Passed
					//}
					for ip, real := range s.Reals {
						health[ip] = real.Probe.Passed
					}

					key := &bpf_service{vip: vip, port: l4.NP(), protocol: l4.PN()}
					val := &be_state{fallback: s.FallbackOn, sticky: s.Sticky, leastconns: s.LeastconnsIP, weight: s.LeastconnsWeight, health: health, backend: report.Backends}

					now := time.Now()

					if update_backend(val, state[l4service], l) {
						m.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
						l.INFO("balancer", "Updated table for ", vip, l4, val.bpf_backend.hash[:32], time.Now().Sub(now))
						state[l4service] = val
					}
				}
			}

			// remove stale backend stats (vip/rip/port/protocol)
			for k, _ := range stats {
				if _, ok := targets[k]; !ok {
					vr := bpf_vrpp{vip: k.VIP, rip: k.RIP, port: htons(k.Port), protocol: k.Protocol}
					xdp.BpfMapDeleteElem(m.vrpp_counter(), uP(&vr))
					xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
					vr.pad = 1
					xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
					mu.Lock()
					delete(stats, k)
					mu.Unlock()
				}
			}

			// remove stale l4 service backend records (vip/port/protocol)
			for k, _ := range state {
				if _, ok := services[k]; !ok {
					s := bpf_service{vip: k.vip, port: k.svc.NP(), protocol: k.svc.PN()}
					xdp.BpfMapDeleteElem(m.service_backend(), uP(&s))
					delete(state, k)
				}
			}

			// remove stale vip records (vip/port/protocol)
			for vip, _ := range vips {
				if _, ok := report.Virtual[vip]; !ok {
					s := bpf_service{vip: vip}
					xdp.BpfMapDeleteElem(m.service_backend(), uP(&s))
				}
				delete(vips, vip) // ??? block above?
			}
		}
	}()

	ch <- c
	return ch, get_stats
}

func update_backend(curr, prev *be_state, l types.Logger) bool {

	if !curr.diff(prev) {
		return false
	}

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

	if !curr.leastconns.IsNil() {
		//fmt.Println(curr.leastconns)
		if b, ok := curr.backend[curr.leastconns]; ok {
			flag[1] = curr.weight
			rip = b.IP
			mac = b.MAC
			vid = b.VID
		}
	}

	curr.bpf_backend.real[0] = bpf_real{rip: rip, mac: mac, vid: htons(vid), flag: flag}

	return true
}
