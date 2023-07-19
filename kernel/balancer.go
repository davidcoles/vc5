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
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/davidcoles/vc5/kernel/bpf"
	"github.com/davidcoles/vc5/kernel/xdp"
	"github.com/davidcoles/vc5/types"
)

const (
	A = false
	B = true
)

type l4Service struct {
	vip IP4
	svc L4
}

type Counter struct {
	Octets      uint64
	Packets     uint64
	Flows       uint64
	Concurrent  uint64
	Blocked     uint64
	Latency     uint64 // global only
	QueueFailed uint64 // global only
	DEFCON      uint8  // global only
}

type Balancer struct {
	maps   *maps
	checks chan Healthchecks
	stats  map[Target]bool
	conns  map[Target]bpf_active
	mutex  sync.Mutex
	logger types.Logger
}

func (m *maps) Balancer(c Healthchecks, l types.Logger) *Balancer {
	b := &Balancer{maps: m, logger: l, checks: make(chan Healthchecks)}
	go b.balancer()
	b.checks <- c
	return b
}

func (b *Balancer) Close() {
	close(b.checks)
}

func (b *Balancer) Configure(r Healthchecks) {
	b.checks <- r
}

func (b *Balancer) Stats() map[Target]Counter {
	// local copies of stats to fill in
	stats := map[Target]Counter{}
	conns := map[Target]bpf_active{}

	b.mutex.Lock()
	for k, _ := range b.stats {
		stats[k] = Counter{}
	}
	for k, v := range b.conns {
		conns[k] = v
	}
	b.mutex.Unlock()

	for k, _ := range stats {
		var bc bpf_counter
		vrrp := bpf_vrpp{vip: k.VIP, rip: k.RIP, port: htons(k.Port), protocol: k.Protocol}
		b.maps.lookup_vrpp_counter(&vrrp, &bc)
		stats[k] = Counter{Octets: bc.octets, Packets: bc.packets, Flows: bc.flows, Concurrent: uint64(conns[k].current)}
	}

	return stats
}

func (b *Balancer) StoreFlow(fs []byte) {

	if len(fs) != bpf.FLOW_S+bpf.STATE_S {
		return
	}

	flow := uP(&fs[0])
	state := uP(&fs[bpf.FLOW_S])
	time := (*uint32)(state)
	*time = uint32(xdp.KtimeGet()) // set first 4 bytes of state to the local kernel time
	xdp.BpfMapUpdateElem(b.maps.flow_shared(), flow, state, xdp.BPF_ANY)
}

func (b *Balancer) FlowQueue() []byte {
	var entry [bpf.FLOW_S + bpf.STATE_S]byte

	if xdp.BpfMapLookupAndDeleteElem(b.maps.flow_queue(), nil, uP(&entry)) != 0 {
		return nil
	}

	return entry[:]
}

func (b *Balancer) BlockList(list [PREFIXES]bool) {
	var table [PREFIXES / 64]uint64
	for n := 0; n < PREFIXES/64; n++ {
		var val uint64
		for m := 0; m < 64; m++ {
			if list[(n*64)+m] {
				val |= pow(m)
			}
		}

		table[n] = val
	}

	b.maps.update_drop_map(table)
	b.maps.features.BLOCKLIST = true
	b.maps.write_settings()
}

func (b *Balancer) NoBlockList() {
	var table [PREFIXES / 64]uint64
	b.maps.update_drop_map(table)
	b.maps.features.BLOCKLIST = false
	b.maps.write_settings()
}

func (b *Balancer) Global() Counter {
	g := b.maps.lookup_globals()
	return Counter{Octets: g.rx_octets, Packets: g.rx_packets, Flows: g.new_flows, QueueFailed: g.qfailed, Latency: g.latency(), DEFCON: b.maps.defcon, Blocked: g.blocked}
}

func (b *Balancer) balancer() {
	FACILITY := "balancer"

	b.stats = map[Target]bool{} // list of stats to collect - not values!
	b.conns = map[Target]bpf_active{}

	done := make(chan bool)
	defer close(done)
	go b.connections(done)

	state := map[l4Service]*be_state{}
	vips := map[IP4]bool{}

	for h := range b.checks {

		b.logger.DEBUG(FACILITY, "Configuration update")

		if false {
			fmt.Println(h.JSON())
		}

		services := map[l4Service]bool{}
		targets := map[Target]bool{}

		interfaces := scanifs()
		for vlanid, prefix := range h.VLANs() {
			iface, _ := interfaces[prefix]

			b.logger.DEBUG("Writing redirect map", vlanid, prefix, iface.mac.String(), iface.index)

			_vlanid := uint32(vlanid)
			_ifindex := uint32(iface.index)

			xdp.BpfMapUpdateElem(b.maps.redirect_mac(), uP(&_vlanid), uP(&(iface.mac)), xdp.BPF_ANY)
			xdp.BpfMapUpdateElem(b.maps.redirect_map(), uP(&_vlanid), uP(&(_ifindex)), xdp.BPF_ANY)
		}

		for vip, virtual := range h.Virtual {

			for l4, service := range virtual.Services {
				b.update_backend_service(vip, l4, service, state)
				b.create_counters(vip, l4, service.Reals, targets)
				services[l4Service{vip: vip, svc: l4}] = true // add to log of active services
			}

			b.maps.update_vrpp_counter(&bpf_vrpp{vip: vip}, &bpf_counter{}, xdp.BPF_NOEXIST) // ICMP responder
			vips[vip] = true
		}

		b.remove_stale_stats(targets)
		b.remove_stale_l4(state, services)

		for vip, _ := range vips {
			if _, ok := h.Virtual[vip]; !ok {
				fmt.Println(xdp.BpfMapDeleteElem(b.maps.vrpp_counter(), uP(&bpf_vrpp{vip: vip}))) // remove ICMP responder
				delete(vips, vip)
			}
		}
	}
}

func (b *Balancer) update_backend_service(vip IP4, l4 L4, s Service, state map[l4Service]*be_state) {
	l4service := l4Service{vip: vip, svc: l4}

	bpf_reals := map[IP4]bpf_real{}
	for ip, real := range s.Reals {
		if real.Probe.Passed {
			bpf_reals[ip] = bpf_real{rip: ip, mac: real.MAC, vid: htons(real.VID)}
		}
	}

	key := &bpf_service{vip: vip, port: l4.NP(), protocol: l4.PN()}
	val := &be_state{
		fallback:  s.FallbackOn,
		sticky:    s.Sticky,
		bpf_reals: bpf_reals,
	}

	if s.Leastconns {
		val.leastconns = s.LeastconnsIP
		val.weight = s.LeastconnsWeight
	}

	now := time.Now()

	if update_backend(val, state[l4service], b.logger) {
		b.maps.update_service_backend(key, &(val.bpf_backend), xdp.BPF_ANY)
		b.logger.INFO("balancer", "Updated table for ", vip, l4, val.bpf_backend.hash[:32], time.Now().Sub(now))
		state[l4service] = val
	}

}

func (b *Balancer) connections(done chan bool) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var era uint8

	for {
		select {
		case <-done:
			return

		case <-ticker.C:

			stats := map[Target]bool{}
			conns := map[Target]bpf_active{}

			// grab a copy of the list stats that we're interested in
			b.mutex.Lock()
			for k, v := range b.stats {
				stats[k] = v
			}
			b.mutex.Unlock()

			era++
			old := era%2 == 0

			b.maps.Era(era) // write back new setting to kernel

			// iterate over the selection reading counters at our leisure
			for v, _ := range stats {
				var a bpf_active
				vrrp := bpf_vrpp{vip: v.VIP, rip: v.RIP, port: htons(v.Port), protocol: v.Protocol}
				b.maps.lookup_vrpp_concurrent(old, &vrrp, &a)                 // lookup previous counter
				b.maps.update_vrpp_concurrent(old, &vrrp, nil, xdp.BPF_EXIST) // clear previous counter

				conns[v] = a
			}

			// write counters back to the visible copy
			b.mutex.Lock()
			b.conns = conns
			b.mutex.Unlock()
		}
	}
}

func (b *Balancer) create_counters(vip IP4, l4 L4, reals map[IP4]Real, targets map[Target]bool) {
	m := b.maps

	// ensure that backend counters for the service exists
	for rip, _ := range reals {
		vr := bpf_vrpp{vip: vip, rip: rip, port: htons(l4.Port), protocol: l4.Protocol.Number()}
		m.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
		m.update_vrpp_concurrent(A, &vr, nil, xdp.BPF_NOEXIST) // create 'A' counter if it does not exist
		m.update_vrpp_concurrent(B, &vr, nil, xdp.BPF_NOEXIST) // create 'B' counter if it does not exist
		target := Target{VIP: vip, RIP: rip, Port: l4.Port, Protocol: l4.Protocol.Number()}

		b.mutex.Lock()
		b.stats[target] = true
		targets[target] = true
		b.mutex.Unlock()
	}
}

func (b *Balancer) remove_stale_stats(targets map[Target]bool) {
	m := b.maps

	for k, _ := range b.stats {
		if _, ok := targets[k]; !ok {
			vr := bpf_vrpp{vip: k.VIP, rip: k.RIP, port: htons(k.Port), protocol: k.Protocol}
			xdp.BpfMapDeleteElem(m.vrpp_counter(), uP(&vr))
			xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))
			vr.pad = 1
			xdp.BpfMapDeleteElem(m.vrpp_concurrent(), uP(&vr))

			b.mutex.Lock()
			delete(b.stats, k)
			b.mutex.Unlock()
		}
	}
}
func (b *Balancer) remove_stale_l4(state map[l4Service]*be_state, services map[l4Service]bool) {
	for k, _ := range state {
		if _, ok := services[k]; !ok {
			s := bpf_service{vip: k.vip, port: k.svc.NP(), protocol: k.svc.PN()}
			xdp.BpfMapDeleteElem(b.maps.service_backend(), uP(&s))
			delete(state, k)
		}
	}
}

func update_backend(curr, prev *be_state, l types.Logger) bool {

	if !curr.diff(prev) {
		return false
	}

	var flag [4]byte

	//const F_STICKY = 0x01
	//const F_FALLBACK = 0x02

	if curr.sticky {
		flag[0] |= bpf.F_STICKY
	}

	if curr.fallback {
		flag[0] |= bpf.F_FALLBACK
	}

	mapper := map[[4]byte]uint8{}
	list := IP4s(make([]IP4, 0, len(curr.bpf_reals)))

	for ip, _ := range curr.bpf_reals {
		list = append(list, ip)
	}

	sort.Sort(list)

	var real [256]bpf_real

	for i, ip := range list {
		if i < 255 {
			idx := uint8(i) + 1
			mapper[ip] = idx
			real[idx] = curr.bpf_reals[ip]
		} else {
			fmt.Println("more than 255 hosts", ip, i)
		}
	}

	curr.bpf_backend.real = real
	curr.bpf_backend.hash, _ = maglev8192(mapper)

	var rip IP4
	var mac MAC
	var vid [2]byte

	if !curr.leastconns.IsNil() {
		if n, ok := mapper[curr.leastconns]; ok {
			flag[1] = curr.weight
			rip = real[n].rip
			mac = real[n].mac
			vid = real[n].vid
		}
	}

	curr.bpf_backend.real[0] = bpf_real{rip: rip, mac: mac, vid: vid, flag: flag}

	return true
}

type be_state struct {
	sticky      bool
	fallback    bool
	leastconns  IP4
	weight      uint8
	bpf_backend bpf_backend
	bpf_reals   map[IP4]bpf_real
}

func bpf_reals_differ(a, b map[IP4]bpf_real) bool {
	for k, v := range a {
		if x, ok := b[k]; !ok {
			return true
		} else {
			if x != v {
				return true
			}
		}
	}

	for k, _ := range b {
		if _, ok := a[k]; !ok {
			return true
		}
	}

	return false
}

func (curr *be_state) diff(prev *be_state) bool {

	if prev == nil {
		return true
	}

	if curr.sticky != prev.sticky ||
		curr.fallback != prev.fallback ||
		curr.leastconns != prev.leastconns ||
		curr.weight != prev.weight {
		return true
	}

	if bpf_reals_differ(curr.bpf_reals, prev.bpf_reals) {
		return true
	}

	return false
}

type iface struct {
	index int
	mac   MAC
}

func scanifs() (ret map[string]iface) {

	ret = map[string]iface{}

	ifaces, err := net.Interfaces()

	if err != nil {
		return
	}

	for _, i := range ifaces {

		if i.Flags&net.FlagLoopback != 0 {
			continue
		}

		if i.Flags&net.FlagUp == 0 {
			continue
		}

		if i.Flags&net.FlagBroadcast == 0 {
			continue
		}

		if len(i.HardwareAddr) != 6 {
			continue
		}

		var mac MAC
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {
				cidr := a.String()
				ip, ipnet, err := net.ParseCIDR(cidr)
				if err == nil && ip.To4() != nil {
					ret[ipnet.String()] = iface{index: i.Index, mac: mac}
				}
			}
		}
	}

	return
}
