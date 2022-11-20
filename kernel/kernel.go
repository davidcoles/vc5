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
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/maglev"
	"github.com/davidcoles/vc5/monitor"
	//"github.com/davidcoles/vc5/rendezvous"
	"github.com/davidcoles/vc5/types"
	"github.com/davidcoles/vc5/xdp"
)

//go:embed bpf/bpf.o
var BPF_O []byte

type uP = unsafe.Pointer
type IP4 = types.IP4
type IP4s = types.IP4s
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

type bpf_real struct {
	rip [4]byte
	mac [6]byte
	vid [2]byte //__be16
	pad [4]byte
}

type bpf_vrpp struct {
	vip      [4]byte //__be32 vip;
	rip      [4]byte //__be32 rip;
	port     [2]byte //__be16 port;
	protocol byte    //__u8 protocol;
	pad      byte    //__u8 pad;
}

type bpf_counter struct {
	packets uint64 //__u64 packets;
	octets  uint64 //__u64 octets;
}

type bpf_setting struct {
	defcon uint8
	era    uint8
}

type bpf_global struct {
	rx_packets     uint64
	rx_octets      uint64
	packets        uint64
	timens         uint64
	perf_timer     uint64
	settings_timer uint64
	defcon         uint64
	dropped        uint64
}

type bpf_service struct {
	vip      [4]byte
	port     [2]byte
	protocol uint8
	pad      uint8
}

type bpf_backend struct {
	hash [8192]byte
	real [256]bpf_real
	flag [8]byte
}

type bpf_vipmac struct {
	vip [4]byte
	mac [6]byte
}

type bpf_nat struct {
	vip     [4]byte
	mac     [6]byte
	srcmac  [6]byte
	srcip   [4]byte
	ifindex uint32
}

type real_info struct {
	idx uint16
	mac MAC
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

func (c *bpf_counter) add(a bpf_counter) {
	c.octets += a.octets
	c.packets += a.packets
}

func (g *bpf_global) add(a bpf_global) {
	g.rx_packets += a.rx_packets
	g.rx_octets += a.rx_octets
	g.packets += a.packets
	g.timens += a.timens
	g.defcon = a.defcon
}

func Open(bond string, native bool, eth ...string) *Maps {
	var m maps
	m.m = make(map[string]int)

	x, err := xdp.LoadBpfFile_(BPF_O, "xdp_main", native, bond, eth...)

	if err != nil {
		log.Fatal(err)
	}

	// balancer
	m.m["service_rec"] = find_map(x, "service_rec", 8, 16*256)
	m.m["service_maglev"] = find_map(x, "service_maglev", 4, 256)
	m.m["service_backend"] = find_map(x, "service_backend", 8, 8192+(256*16)+8)

	// nat
	m.m["nat_to_vip_mac"] = find_map(x, "nat_to_vip_mac", 4, 24)
	m.m["vip_mac_to_nat"] = find_map(x, "vip_mac_to_nat", 10, 24)

	// stats
	m.m["globals"] = find_map(x, "globals", 4, 64)
	m.m["vrpp_counter"] = find_map(x, "vrpp_counter", 12, 16)

	// control
	m.m["settings"] = find_map(x, "settings", 4, 2)

	var zero uint32
	s := bpf_setting{defcon: 5, era: 0}

	if xdp.BpfMapUpdateElem(m.settings(), uP(&zero), uP(&s), xdp.BPF_ANY) != 0 {
		panic("oops")
	}

	return &m
}

func (m *maps) service_rec() int     { return m.m["service_rec"] }
func (m *maps) service_maglev() int  { return m.m["service_maglev"] }
func (m *maps) service_backend() int { return m.m["service_backend"] }
func (m *maps) nat_to_vip_mac() int  { return m.m["nat_to_vip_mac"] }
func (m *maps) vip_mac_to_nat() int  { return m.m["vip_mac_to_nat"] }
func (m *maps) vrpp_counter() int    { return m.m["vrpp_counter"] }
func (m *maps) globals() int         { return m.m["globals"] }
func (m *maps) settings() int        { return m.m["settings"] }

func (m *maps) update_service_rec(sk bpf_service, sr [256]bpf_real, flag uint64) int {

	all := make([][256]bpf_real, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = sr
	}

	return xdp.BpfMapUpdateElem(m.service_rec(), uP(&sk), uP(&(all[0])), flag)
}

func (m *maps) update_service_maglev(sn uint8, b [65536]byte) int {

	type slice [256]byte

	for x := 0; x < 256; x++ {

		var key uint32 = (uint32(sn) << 8) | (uint32(x) & 0xff)
		var val slice

		copy(val[:], b[(x*256):])

		all := make([]slice, xdp.BpfNumPossibleCpus())

		for n, _ := range all {
			all[n] = val
		}

		xdp.BpfMapUpdateElem(m.service_maglev(), uP(&key), uP(&(all[0])), xdp.BPF_ANY) // array
	}

	return 0
}

func (m *maps) update_service_backend(key *bpf_service, b *bpf_backend, flag uint64) int {

	all := make([]bpf_backend, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *b
	}

	return xdp.BpfMapUpdateElem(m.service_backend(), uP(key), uP(&(all[0])), flag)
}

func (m *maps) update_vrpp_counter(v *bpf_vrpp, c *bpf_counter, flag uint64) int {

	all := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *c
	}

	return xdp.BpfMapUpdateElem(m.vrpp_counter(), uP(v), uP(&(all[0])), flag)
}

func (m *maps) lookup_vrpp_counter(v *bpf_vrpp, c *bpf_counter) int {

	co := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	ret := xdp.BpfMapLookupElem(m.vrpp_counter(), uP(v), uP(&(co[0])))

	var x bpf_counter

	for _, v := range co {
		x.add(v)
	}

	*c = x

	return ret
}

func (m *maps) GlobalStats() (uint64, uint64, uint64, uint8) {
	var g bpf_global
	m.lookup_globals(&g)

	var latency uint64
	if g.packets > 0 {
		latency = g.timens / g.packets
	}

	return g.rx_packets, g.rx_octets, latency, uint8(g.defcon)
}

func (m *maps) DEFCON(d uint8) uint8 {

	var zero uint32
	var s bpf_setting

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

func (m *maps) lookup_globals(g *bpf_global) int {

	all := make([]bpf_global, xdp.BpfNumPossibleCpus())
	var zero uint32

	ret := xdp.BpfMapLookupElem(m.globals(), uP(&zero), uP(&(all[0])))

	var x bpf_global

	for _, v := range all {
		x.add(v)
	}

	*g = x

	return ret
}

func (m *maps) NAT(myip IP4, h *Healthchecks, bond, veth int, vc5aip, vc5bip IP4, vc5amac, vc5bmac MAC) (chan *Healthchecks, func(ip IP4) (MAC, bool)) {

	var mu sync.Mutex

	macs := map[IP4]MAC{}
	local := map[IP4]MAC{}

	ch := make(chan *Healthchecks)

	get_mac_for_ip := func(ip IP4) (MAC, bool) {
		mu.Lock()
		m, ok := macs[ip]
		mu.Unlock()
		return m, ok
	}

	macs = arp_macs()
	local = local_macs()

	go func() {
		time.Sleep(2 * time.Second)
		for {
			m := arp_macs()
			mu.Lock()
			macs = m
			mu.Unlock()

			select {
			case <-time.After(10 * time.Second):
			}
		}
	}()

	go func() {

		type record struct {
			vm  bpf_vipmac
			in  bpf_nat
			out bpf_nat
		}

		pings := map[IP4]chan bool{}
		recs := map[uint16]record{}

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

				mac, _ := get_mac_for_ip(rip)
				vm := bpf_vipmac{vip: vip, mac: mac}

				mymac, ok := local[myip]

				//log.Println(myip, mymac, ok)

				if !ok {
					log.Fatal(myip, mymac, ok)
				}

				out := bpf_nat{vip: vip, mac: mac, srcmac: mymac, srcip: myip, ifindex: uint32(bond)}
				in := bpf_nat{vip: vc5bip, mac: vc5bmac, srcip: nat, ifindex: uint32(veth)}

				localhost := IP4{127, 0, 0, 1}
				if rip == localhost {
					out.ifindex = 0
					in.ifindex = 0
					vm.mac = vc5amac
					out.srcip = vc5bip
				}

				var update bool = true
				rec := record{vm: vm, in: in, out: out}

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
					fmt.Println("WRITING", nat, rip, vm)
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

	ch <- h
	return ch, get_mac_for_ip
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

func (m *maps) Balancer(c Report) (chan Report, func() map[Target]Counter) {

	type service_val [256]bpf_real
	type l4Service struct {
		vip IP4
		svc L4
	}

	M := map[l4Service]uint8{}
	var I []uint8
	for n := 0; n < 256; n++ {
		I = append(I, uint8(n))
	}

	ch := make(chan Report)

	// stats ...
	stats := map[Target]bool{}
	var mu sync.Mutex

	get_stats := func() map[Target]Counter {
		r := map[Target]Counter{}
		s := map[Target]bool{}

		mu.Lock()
		for k, v := range stats {
			s[k] = v
		}
		mu.Unlock()

		for v, _ := range s {
			vr := bpf_vrpp{vip: v.VIP, rip: v.RIP, port: htons(v.Port), protocol: v.Protocol}
			co := bpf_counter{}
			m.lookup_vrpp_counter(&vr, &co)
			r[v] = Counter{Octets: co.octets, Packets: co.packets}
		}

		return r
	}

	go func() {
		for config := range ch {

			fmt.Println(config)

			M_ := map[l4Service]uint8{}

			for vip, s := range config.Virtuals {
				for l4, serv := range s.Services {

					now := time.Now()

					for n, _ := range serv.Health {
						if be, ok := config.Backends[n]; ok {
							vr := bpf_vrpp{vip: vip, rip: be.IP, port: htons(l4.Port), protocol: l4.Protocol.Number()}
							m.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
							b := Target{VIP: vip, RIP: be.IP, Port: l4.Port, Protocol: l4.Protocol.Number()}
							mu.Lock()
							stats[b] = true
							mu.Unlock()
						}
					}

					l4s := l4Service{vip: vip, svc: l4}

					M_[l4s] = 0

					i, ok := M[l4s]

					if !ok {
						i = I[0]
						I = I[1:]
						M[l4s] = i
					}

					fmt.Println(i, vip, l4, serv)

					var sv service_val
					for k, v := range config.Backends {
						sv[k] = bpf_real{rip: v.IP, mac: v.MAC, vid: [2]byte{0, 0}, pad: [4]uint8{0, 0, 0, 0}}
					}
					sv[0] = bpf_real{pad: [4]uint8{i, 0, 0, 0}}

					s := map[[4]byte]uint8{}

					for k, up := range serv.Health {
						if be, ok := config.Backends[k]; ok && up {
							s[be.IP] = uint8(k)
						}
					}

					mag, _ := MaglevIPU8(s)

					//fmt.Println(sv[0:10], mag[:64])

					bs := bpf_service{
						vip:      vip,
						port:     htons(l4.Port),
						protocol: l4.Protocol.Number(),
					}

					m.update_service_maglev(i, mag)
					m.update_service_rec(bs, sv, xdp.BPF_ANY)

					fmt.Println("****", time.Now().Sub(now))
				}
			}

			for k, v := range M {
				if _, ok := M_[k]; !ok {
					s := bpf_service{
						vip:      k.vip,
						port:     htons(k.svc.Port),
						protocol: k.svc.Protocol.Number(),
					}
					xdp.BpfMapDeleteElem(m.service_rec(), uP(&s))
					delete(M, k)
					I = append(I, v)
				}
			}

			fmt.Println("======================================================================")
		}
	}()

	ch <- c
	return ch, get_stats
}

/*
func (m *maps) _Balancer(c Report) (chan Report, func() map[Target]Counter) {
	ch := make(chan Report)

	stats := map[Target]bool{}
	var mu sync.Mutex

	get_stats := func() map[Target]Counter {
		r := map[Target]Counter{}
		s := map[Target]bool{}

		mu.Lock()
		for k, v := range stats {
			s[k] = v
		}
		mu.Unlock()

		for v, _ := range s {
			vr := bpf_vrpp{vip: v.VIP, rip: v.RIP, port: htons(v.Port), protocol: v.Protocol}
			co := bpf_counter{}
			m.lookup_vrpp_counter(&vr, &co)
			r[v] = Counter{Octets: co.octets, Packets: co.packets}
		}

		return r
	}

	go func() {

		type l4Service struct {
			vip IP4
			svc L4
		}

		type l4State struct {
			real_info     map[IP4]real_info
			backend       *bpf_backend
			service_index uint8
		}

		state := map[l4Service]l4State{}

		for config := range ch {

			// remove any entries which no longer exist in config
			// might be useful to leave real server counters in place to record
			// residual traffic for hosts which have been removed from config
			for k, _ := range state {
				vip := k.vip
				port := htons(k.svc.Port)
				proto := k.svc.Protocol.Number()

				s, ok := config.Virtuals[vip]

				if ok {
					_, ok = s.Services[k.svc]
				}

				if !ok {
					delete(state, k)
					fmt.Println("DELETE", k.vip, k.svc)

					s := bpf_service{vip: k.vip, port: port, protocol: proto}
					xdp.BpfMapDeleteElem(m.service_backend(), uP(&s))
				}
			}

			for vip, s := range config.Virtuals {

				co := bpf_counter{}
				vr := bpf_vrpp{vip: vip, rip: [4]byte{}, port: htons(0), protocol: 0}
				m.update_vrpp_counter(&vr, &co, xdp.BPF_NOEXIST)
				m.lookup_vrpp_counter(&vr, &co)
				//fmt.Println("MISSES", vr, co)

				for l4, serv := range s.Services {
					port := htons(l4.Port)
					proto := l4.Protocol.Number()

					for n, _ := range serv.Health {
						if be, ok := config.Backends[n]; ok {
							vr := bpf_vrpp{vip: vip, rip: be.IP, port: port, protocol: proto}
							m.update_vrpp_counter(&vr, &bpf_counter{}, xdp.BPF_NOEXIST)
							b := Target{VIP: vip, RIP: be.IP, Port: l4.Port, Protocol: proto}
							mu.Lock()
							stats[b] = true
							mu.Unlock()
						}
					}

					l4service := l4Service{vip: vip, svc: l4}

					new := map[IP4]real_info{}
					old := map[IP4]real_info{}

					var backends *bpf_backend

					if l4state, ok := state[l4service]; ok {
						old = l4state.real_info
						backends = l4state.backend
					}

					for n, up := range serv.Health {
						if be, ok := config.Backends[n]; up && ok {
							new[be.IP] = real_info{idx: n, mac: be.MAC}
						}
					}

					backends = m.update_backend(vip, l4, new, old, backends, serv.Fallback)
					state[l4service] = l4State{real_info: new, backend: backends}

				}
			}
		}
	}()

	ch <- c
	return ch, get_stats
}
*/
func ip4mackeys(a map[IP4]real_info, b map[IP4]real_info, v bool) bool {

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

/*
func (m *maps) _update_backend(vip IP4, l4 L4, curr map[IP4]real_info, old map[IP4]real_info, b *bpf_backend, fallback bool) *bpf_backend {

	var be bpf_backend

	if b != nil {
		be = *b
	}

	if fallback {
		be.flag[0] = 1
	} else {
		be.flag[0] = 0
	}

	if b == nil || !ip4mackeys(curr, old, false) {
		nodes := map[[4]byte]uint16{}
		for k, v := range curr {
			nodes[k] = v.idx
		}
		// recalculate hashes
		hash, stats := rendezvous.RipIndex(nodes)
		copy(be.hash[:], hash[:])
		fmt.Println("RECALC", vip, l4, stats, hash[0:32])
	}

	for k, v := range curr {
		var r bpf_real
		r.rip = k
		r.mac = v.mac
		be.real[v.idx] = r
	}

	if b != nil && be == *b {
		return b
	}

	s := bpf_service{vip: vip, port: htons(l4.Port), protocol: l4.Protocol.Number()}

	//fmt.Println(s, be, curr)
	fmt.Println("WRITING", vip, l4)

	m.update_service_backend(&s, &be, xdp.BPF_ANY)

	return &be
}
*/
/*
func (m *maps) update_backend(vip IP4, l4 L4, curr map[IP4]real_info, old map[IP4]real_info, b *bpf_backend, fallback bool) *bpf_backend {

	var be bpf_backend

	if b != nil {
		be = *b
	}

	if fallback {
		be.flag[0] = 1
	} else {
		be.flag[0] = 0
	}

	if b == nil || !ip4mackeys(curr, old, false) {
		nodes := map[[4]byte][6]byte{}
		for k, v := range curr {
			nodes[k] = v.mac
		}

		table, stats := maglev.IP(nodes)

		var hash [8192]byte
		var idx uint16 = 1
		idxs := map[IP4]byte{}

		for k, v := range nodes {
			if idx > 255 {
				panic("idx too big")
			}

			idxs[k] = byte(idx)

			var r bpf_real
			r.rip = k
			r.mac = v

			be.real[idx] = r

			idx++
		}

		for k, v := range table {
			hash[k] = idxs[v]
		}

		copy(be.hash[:], hash[:])
		fmt.Println("RECALC", vip, l4, stats, hash[0:32])
	}

	if b != nil && be == *b {
		return b
	}

	s := bpf_service{vip: vip, port: htons(l4.Port), protocol: l4.Protocol.Number()}

	//fmt.Println(s, be, curr)
	fmt.Println("WRITING", vip, l4)

	m.update_service_backend(&s, &be, xdp.BPF_ANY)

	return &be
}
*/
/**********************************************************************/

/*
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
*/

/**********************************************************************/

func MaglevIPU8(m map[[4]byte]uint8) (r [65536]uint8, b bool) {

	if len(m) < 1 {
		return r, false
	}

	a := IP4s(make([]IP4, len(m)))

	n := 0
	for k, _ := range m {
		//fmt.Println(k, n)
		a[n] = k
		n++
	}

	sort.Sort(a)

	h := make([][]byte, len(a))

	for k, v := range a {
		b := make([]byte, 4)
		copy(b[:], v[:])
		h[k] = b
		//fmt.Println("xxx", k, v, h[k])
	}

	t := maglev.Maglev65536(h)

	//fmt.Println(">>>", a, h, t[:64])

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
