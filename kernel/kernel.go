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
	"bufio"
	_ "embed"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"
	"unsafe"

	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/maglev"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/rendezvous"
	"github.com/davidcoles/vc5/types"
	"github.com/davidcoles/vc5/xdp"
)

//go:embed bpf/test.o
var TEST_O []byte

type uP = unsafe.Pointer
type IP4 = types.IP4
type MAC = types.MAC
type L4 = types.L4
type Protocol = types.Protocol

type Metadata = healthchecks.Metadata
type Reals map[uint16]Real
type Real = healthchecks.Real
type Service_ = healthchecks.Service
type Virtual_ = healthchecks.Virtual
type Healthchecks = healthchecks.Healthchecks
type NAT = healthchecks.NAT

type Status = monitor.Status
type Virtual = monitor.Virtual
type Report = monitor.Report

type maps = Maps
type Maps struct {
	m map[string]int
}

type mag struct {
	vip      [4]byte
	port     [2]byte
	hash     uint16
	protocol uint8
	pad      [3]uint8
}

type real struct {
	rip [4]byte
	mac [6]byte
	vid [2]byte //__be16
	pad [4]byte
}

type vrpp struct {
	vip      [4]byte //__be32 vip;
	rip      [4]byte //__be32 rip;
	port     [2]byte //__be16 port;
	protocol byte    //__u8 protocol;
	pad      byte    //__u8 pad;
}

type counter struct {
	packets uint64 //__u64 packets;
	octets  uint64 //__u64 octets;
}

type setting struct {
	defcon uint8
	era    uint8
}

type global struct {
	rx_packets     uint64
	rx_octets      uint64
	packets        uint64
	timens         uint64
	perf_timer     uint64
	settings_timer uint64
	defcon         uint64
	dropped        uint64
}

func (c *counter) add(a counter) {
	c.octets += a.octets
	c.packets += a.packets
}

func (g *global) add(a global) {
	g.rx_packets += a.rx_packets
	g.rx_octets += a.rx_octets
	g.packets += a.packets
	g.timens += a.timens
	g.defcon = a.defcon
}

func Open(native bool, eth ...string) *Maps {
	var m maps
	m.m = make(map[string]int)

	//var native bool

	x, err := xdp.LoadBpfFile_(TEST_O, "xdp_main", native, eth...)

	if err != nil {
		log.Fatal(err)
	}

	// balancer
	m.m["maglev_real"] = find_map(x, "maglev_real", 12, 16)
	m.m["service_backend"] = find_map(x, "service_backend", 8, 8192+(256*16))

	// nat
	m.m["nat_to_vip_mac"] = find_map(x, "nat_to_vip_mac", 4, 24)
	m.m["vip_mac_to_nat"] = find_map(x, "vip_mac_to_nat", 10, 24)

	// stats
	m.m["globals"] = find_map(x, "globals", 4, 64)
	m.m["vrpp_counter"] = find_map(x, "vrpp_counter", 12, 16)

	// control
	m.m["settings"] = find_map(x, "settings", 4, 2)

	var zero uint32
	s := setting{defcon: 5, era: 0}

	if xdp.BpfMapUpdateElem(m.settings(), uP(&zero), uP(&s), xdp.BPF_ANY) != 0 {
		panic("oops")
	}

	return &m
}

func (m *maps) maglev_real() int     { return m.m["maglev_real"] }
func (m *maps) service_backend() int { return m.m["service_backend"] }

func (m *maps) nat_to_vip_mac() int { return m.m["nat_to_vip_mac"] }
func (m *maps) vip_mac_to_nat() int { return m.m["vip_mac_to_nat"] }
func (m *maps) vrpp_counter() int   { return m.m["vrpp_counter"] }
func (m *maps) globals() int        { return m.m["globals"] }
func (m *maps) settings() int       { return m.m["settings"] }

func (m *maps) update_service_backend(key *service, b *backend, flag uint64) int {

	all := make([]backend, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *b
	}

	return xdp.BpfMapUpdateElem(m.service_backend(), uP(key), uP(&(all[0])), flag)
}

func (m *maps) update_maglev_real(key *mag, b *real, flag uint64) int {

	all := make([]real, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *b
	}

	return xdp.BpfMapUpdateElem(m.maglev_real(), uP(key), uP(&(all[0])), flag)
}

func (m *maps) update_vrpp_counter(v *vrpp, c *counter, flag uint64) int {

	all := make([]counter, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *c
	}

	return xdp.BpfMapUpdateElem(m.vrpp_counter(), uP(v), uP(&(all[0])), flag)
}

func (m *maps) lookup_vrpp_counter(v *vrpp, c *counter) int {

	co := make([]counter, xdp.BpfNumPossibleCpus())

	ret := xdp.BpfMapLookupElem(m.vrpp_counter(), uP(v), uP(&(co[0])))

	var x counter

	for _, v := range co {
		x.add(v)
	}

	*c = x

	return ret
}

func (m *maps) GlobalStats() (uint64, uint64, uint64, uint8) {
	var g global
	m.lookup_globals(&g)

	var latency uint64
	if g.packets > 0 {
		latency = g.timens / g.packets
	}

	return g.rx_packets, g.rx_octets, latency, uint8(g.defcon)
}

func (m *maps) DEFCON(d uint8) uint8 {

	var zero uint32
	var s setting

	if d >= 1 && d <= 5 {
		s.defcon = d

		if xdp.BpfMapUpdateElem(m.settings(), uP(&zero), uP(&s), xdp.BPF_ANY) != 0 {
			panic("oops")
		}
	}

	if xdp.BpfMapLookupElem(m.settings(), uP(&zero), uP(&s)) != 0 {
		panic("oops")
	}

	return s.defcon
}

func (m *maps) lookup_globals(g *global) int {

	all := make([]global, xdp.BpfNumPossibleCpus())
	var zero uint32

	ret := xdp.BpfMapLookupElem(m.globals(), uP(&zero), uP(&(all[0])))

	var x global

	for _, v := range all {
		x.add(v)
	}

	*g = x

	return ret
}

func (m *maps) NAT(myi IP4, h *Healthchecks, bond, veth int, vc5aip, vc5bip IP4, vc5amac, vc5bmac MAC) (chan *Healthchecks, func(ip IP4) (MAC, bool)) {

	var mu sync.Mutex

	macs := map[IP4]MAC{}
	local := map[IP4]MAC{}

	ch := make(chan *Healthchecks, 1)
	ch <- h

	foo := func(ip IP4) (MAC, bool) {
		mu.Lock()
		m, ok := macs[ip]
		mu.Unlock()
		return m, ok
	}

	bar := func() map[IP4]MAC {
		a := arp_macs()
		l := local_macs()
		_macs := map[IP4]MAC{}
		for k, v := range a {
			_macs[k] = v
		}
		for k, v := range l {
			_macs[k] = v
		}
		return _macs
	}

	macs = bar()
	local = local_macs()

	go func() {
		time.Sleep(2 * time.Second)
		for {
			mu.Lock()
			macs = bar()
			mu.Unlock()

			select {
			case <-time.After(10 * time.Second):
			}
		}
	}()

	go func() {

		type VM struct {
			vip [4]byte
			mac [6]byte
		}

		type VME struct {
			vip     [4]byte
			mac     [6]byte
			srcmac  [6]byte
			srcip   [4]byte
			ifindex uint32
		}

		type REC struct {
			vm  VM
			in  VME
			out VME
		}

		pings := map[IP4]chan bool{}

		recs := map[uint16]REC{}

		//for h := range ch {

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {

			select {
			case <-ticker.C:
			case x, ok := <-ch:
				ticker.Reset(20 * time.Second)
				if !ok {
					return
				}
				h = x
			}

			mapping := h.NAT()

			{
				rips := map[IP4]bool{}
				for _, be := range mapping {
					rips[be[1]] = true
				}

				for k, _ := range rips {
					if _, ok := pings[k]; !ok {
						pings[k] = ping(k)
					}
				}

				for k, v := range pings {
					if _, ok := rips[k]; !ok {
						close(v)
						delete(pings, k)
					}
				}
			}

			for n, be := range mapping {
				vip := be[0]
				rip := be[1]
				nat := Nat(n, vc5bip)

				mac, _ := foo(rip)
				vm := VM{vip: vip, mac: mac}

				srcmac, ok := foo(myi)

				if !ok {
					log.Fatal(myi, srcmac, ok)
				}

				out := VME{vip: vip, mac: mac, srcmac: srcmac, srcip: myi, ifindex: uint32(bond)}
				in := VME{vip: vc5bip, mac: vc5bmac, srcip: nat, ifindex: uint32(veth)}

				//fmt.Println("VIP/RIP/MAC", vip, rip, mac)
				_, loc := local[rip]
				if loc {
					out.ifindex = 0
					in.ifindex = 0
					vm.mac = vc5amac
				}

				var update bool = true
				rec := REC{vm: vm, in: in, out: out}

				if v, ok := recs[n]; ok {

					if v == rec {
						update = false
					} else {
						if v.vm != rec.vm {
							fmt.Println("UPDATING", v.vm)
							xdp.BpfMapDeleteElem(m.vip_mac_to_nat(), uP(&(v.vm)))
						}
					}
				}

				recs[n] = rec

				if update {
					fmt.Println("WRITING", nat, vm)
					xdp.BpfMapUpdateElem(m.nat_to_vip_mac(), uP(&nat), uP(&out), xdp.BPF_ANY)
					xdp.BpfMapUpdateElem(m.vip_mac_to_nat(), uP(&vm), uP(&in), xdp.BPF_ANY)
				}
			}

			for n, v := range recs {
				if _, ok := mapping[n]; !ok {
					delete(recs, n)
					nat := Nat(n, vc5bip)
					fmt.Println("REMOVING", nat, v.vm)
					xdp.BpfMapDeleteElem(m.nat_to_vip_mac(), uP(&nat))
					xdp.BpfMapDeleteElem(m.vip_mac_to_nat(), uP(&(v.vm)))
				}
			}
		}
	}()

	return ch, foo
}

func Nat(n uint16, ip IP4) [4]byte {
	hl := htons(n)
	var nat [4]byte
	nat[0] = ip[0]
	nat[1] = ip[1]
	nat[2] = hl[0]
	nat[3] = hl[1]
	return nat
}

type Target struct {
	VIP      IP4
	RIP      IP4
	Port     uint16
	Protocol uint8
}

type Counter struct {
	Octets  uint64
	Packets uint64
}

func find_map(x *xdp.XDP_, name string, ks int, rs int) int {
	m := x.FindMap(name)

	if m == -1 {
		log.Fatal(name, " not found")
	}

	if !x.CheckMap(m, ks, rs) {
		log.Fatal(name, " incorrect size")
	}

	return m
}

func htons(p uint16) [2]byte {
	var hl [2]byte
	hl[0] = byte(p >> 8)
	hl[1] = byte(p & 0xff)
	return hl
}

func find_local(ips []IP4) map[IP4]bool {
	locals := local_addrs()
	ret := map[IP4]bool{}
	for _, ip := range ips {
		_, ok := locals[ip]
		ret[ip] = ok
	}
	return ret
}

func local_addrs() map[IP4]MAC {
	locals := map[IP4]MAC{}

	ifaces, err := net.Interfaces()

	if err == nil {

		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}

			for _, a := range addrs {

				ip, _, err := net.ParseCIDR(a.String())

				if err == nil {

					ip4 := ip.To4()

					if ip4 != nil {
						var mac, nul MAC
						copy(mac[:], i.HardwareAddr)

						if mac != nul {
							locals[IP4{ip4[0], ip4[1], ip4[2], ip4[3]}] = mac
						}
					}
				}
			}
		}
	}

	return locals
}

func arp_macs() map[IP4]MAC {

	ip2mac := make(map[IP4]MAC)
	ip2nic := make(map[IP4]*net.Interface)

	re := regexp.MustCompile(`^(\S+)\s+0x1\s+0x.\s+(\S+)\s+\S+\s+(\S+)$`)

	file, err := os.OpenFile("/proc/net/arp", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) > 3 {

			ip := net.ParseIP(m[1])

			if ip == nil {
				continue
			}

			ip = ip.To4()

			if ip == nil || len(ip) != 4 {
				continue
			}

			hw, err := net.ParseMAC(m[2])

			if err != nil || len(hw) != 6 {
				continue
			}

			iface, err := net.InterfaceByName(m[3])

			if err != nil {
				continue
			}

			var ip4 IP4
			var mac [6]byte

			copy(ip4[:], ip[:])
			copy(mac[:], hw[:])

			if ip4.String() == "0.0.0.0" {
				continue
			}

			if mac == [6]byte{0, 0, 0, 0, 0, 0} {
				continue
			}

			ip2mac[ip4] = mac
			ip2nic[ip4] = iface
		}
	}

	return ip2mac
}

func local_macs() map[IP4]MAC {
	locals := map[IP4]MAC{}

	ifaces, err := net.Interfaces()

	if err == nil {

		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}

			for _, a := range addrs {

				ip, _, err := net.ParseCIDR(a.String())

				if err == nil {

					ip4 := ip.To4()

					if ip4 != nil {
						var mac, nul MAC
						copy(mac[:], i.HardwareAddr)

						if mac != nul {
							locals[IP4{ip4[0], ip4[1], ip4[2], ip4[3]}] = mac
						}
					}
				}
			}
		}
	}

	return locals
}

func ping(ip IP4) chan bool {
	done := make(chan bool)
	go func() {
		fmt.Println("STARTING PING", ip)
		for {
			exec.Command("/usr/bin/ping", "-c1", "-W1", ip.String()).Output()
			select {
			case <-time.After(10 * time.Second):
			case <-done:
				return
			}
		}
	}()
	return done
}

func (m *maps) Balancer3(c Report) (chan Report, func() map[Target]Counter) {
	ch := make(chan Report, 1)
	ch <- c

	stats := map[Target]bool{}
	var mu sync.Mutex

	get_stats := func() map[Target]Counter {
		r := map[Target]Counter{}
		mu.Lock()
		for v, _ := range stats {
			vr := vrpp{vip: v.VIP, rip: v.RIP, port: htons(v.Port), protocol: v.Protocol}
			co := counter{}
			//xdp.BpfMapLookupElem(m.vrpp_counter(), uP(&vr), uP(&co))
			m.lookup_vrpp_counter(&vr, &co)
			r[v] = Counter{Octets: co.octets, Packets: co.packets}
		}
		mu.Unlock()
		return r
	}

	go func() {

		type mysvc struct {
			vip IP4
			svc L4
		}

		type mydat struct {
			rinfo   map[IP4]rinfo
			backend *backend
		}

		mystate := map[mysvc]mydat{}

		for config := range ch {

			var intcache [256]real
			for n, b := range config.Backends {
				intcache[n] = real{rip: b.IP, mac: b.MAC}
			}

			// remove any entries which no longer exist in config
			// might be useful to leave real server counters in place to record
			// residual traffic for hosts which have been removed from config
			for k, _ := range mystate {
				vip := k.vip
				port := htons(k.svc.Port)
				proto := k.svc.Protocol.Number()

				s, ok := config.Virtuals[vip]

				if ok {
					_, ok = s.Services[k.svc]
				}

				if !ok {
					delete(mystate, k)
					fmt.Println("DELETE", k.vip, k.svc)

					s := service{vip: k.vip, port: port, protocol: proto}
					xdp.BpfMapDeleteElem(m.service_backend(), uP(&s))

					for n := 0; n < 65536; n++ {
						mg := mag{vip: k.vip, port: port, protocol: proto, hash: uint16(n)}
						xdp.BpfMapDeleteElem(m.maglev_real(), uP(&mg))
					}
				}
			}

			for vip, s := range config.Virtuals {

				co := counter{}
				vr := vrpp{vip: vip, rip: [4]byte{}, port: htons(0), protocol: 0}
				m.update_vrpp_counter(&vr, &co, xdp.BPF_NOEXIST)
				m.lookup_vrpp_counter(&vr, &co)
				fmt.Println("MISSES", vr, co)

				for l4, serv := range s.Services {
					port := htons(l4.Port)
					proto := l4.Protocol.Number()

					for n, _ := range serv.Health {

						if be, ok := config.Backends[n]; ok {
							vr := vrpp{vip: vip, rip: be.IP, port: port, protocol: proto}
							m.update_vrpp_counter(&vr, &counter{}, xdp.BPF_NOEXIST)
							b := Target{VIP: vip, RIP: be.IP, Port: l4.Port, Protocol: proto}
							mu.Lock()
							stats[b] = true
							mu.Unlock()
						}
					}

					/**********************************************************************/

					{
						nodes := map[[4]byte][6]byte{}

						for n, up := range serv.Health {
							if be, ok := config.Backends[n]; up && ok {
								nodes[be.IP] = be.MAC
							}
						}

						table := maglev.IPs(nodes)

						for i, v := range table {
							mg := mag{vip: vip, port: port, protocol: proto, hash: uint16(i)}
							be := real{rip: v, mac: nodes[v]}
							m.update_maglev_real(&mg, &be, xdp.BPF_ANY)
						}
					}

					/**********************************************************************/

					{
						mys := mysvc{vip: vip, svc: l4}

						sv, ok := mystate[mys]

						c := map[IP4]rinfo{}
						o := map[IP4]rinfo{}
						var b *backend

						if ok {
							o = sv.rinfo
							b = sv.backend
						}

						for n, up := range serv.Health {
							if be, ok := config.Backends[n]; up && ok {
								c[be.IP] = rinfo{idx: n, mac: be.MAC}
							}
						}

						b = m.update_backend(vip, l4, c, o, b)

						mystate[mys] = mydat{rinfo: c, backend: b}
					}

				}
			}
		}
	}()
	return ch, get_stats
}

type service struct {
	vip      [4]byte
	port     [2]byte
	protocol uint8
	pad      uint8
}

type backend struct {
	hash [8192]byte
	real [256]real
}

type rinfo struct {
	idx uint16
	mac MAC
}

func ip4mackeys(a map[IP4]rinfo, b map[IP4]rinfo, v bool) bool {

	for k, _ := range a {
		if _, ok := b[k]; !ok {
			return false
		}
		if v && a[k] != b[k] {
			return false
		}
	}

	for k, _ := range b {
		if _, ok := a[k]; !ok {
			return false
		}
	}

	return true
}

func (m *maps) update_backend(vip IP4, l4 L4, curr map[IP4]rinfo, old map[IP4]rinfo, b *backend) *backend {

	var be backend

	if b != nil {
		be = *b
	}

	if b == nil || !ip4mackeys(curr, old, false) {
		nodes := map[[4]byte]uint16{}
		for k, v := range curr {
			nodes[k] = v.idx
		}
		// recalculate hashes
		hash, stats := rendezvous.RipIndex(nodes)
		be.hash = hash
		fmt.Println("RECALC", vip, l4, stats)
	}

	for k, v := range curr {
		var r real
		r.rip = k
		r.mac = v.mac
		be.real[v.idx] = r
	}

	if b != nil && be == *b {
		return b
	}

	s := service{vip: vip, port: htons(l4.Port), protocol: l4.Protocol.Number()}

	//fmt.Println(s, be, curr)
	fmt.Println("WRITING", vip, l4)

	m.update_service_backend(&s, &be, xdp.BPF_ANY)

	return &be
}
