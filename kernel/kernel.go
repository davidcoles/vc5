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
type Service_ = healthchecks.Service_
type Virtual_ = healthchecks.Virtual_
type Healthchecks = healthchecks.Healthchecks
type NAT = healthchecks.NAT

type Status = monitor.Status
type Virtual = monitor.Virtual
type Report = monitor.Report

type maps = Maps
type Maps struct {
	m map[string]int
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

func Open(eth ...string) *Maps {
	var m maps
	m.m = make(map[string]int)

	var native bool

	x, err := xdp.LoadBpfFile_(TEST_O, "xdp_main", native, eth...)

	if err != nil {
		log.Fatal(err)
	}

	m.m["services"] = find_map(x, "services", 8, 8192)
	m.m["backends"] = find_map(x, "backends", 4, 12)

	m.m["nat_to_vip_mac"] = find_map(x, "nat_to_vip_mac", 4, 24)
	m.m["vip_mac_to_nat"] = find_map(x, "vip_mac_to_nat", 10, 24)

	m.m["vrpp_counter"] = find_map(x, "vrpp_counter", 12, 16)

	return &m
}

func (m *maps) backends() int { return m.m["backends"] }
func (m *maps) services() int { return m.m["services"] }

func (m *maps) nat_to_vip_mac() int { return m.m["nat_to_vip_mac"] }
func (m *maps) vip_mac_to_nat() int { return m.m["vip_mac_to_nat"] }
func (m *maps) vrpp_counter() int   { return m.m["vrpp_counter"] }

func (m *maps) NAT(myi IP4, h *Healthchecks, done chan bool, bond, veth int, vc5aip, vc5bip IP4, vc5amac, vc5bmac MAC) (chan *Healthchecks, func(ip IP4) (MAC, bool)) {

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

			defer close(done)

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

func Lbengine(m *maps, c Report, done chan bool) (chan Report, func() map[Target]Counter) {
	ch := make(chan Report, 1)
	ch <- c

	mapequ := func(a, b map[[4]byte]uint16) bool {
		for k, v := range a {
			x, ok := b[k]

			if !ok || v != x {
				return false
			}
		}

		for k, v := range b {
			x, ok := a[k]

			if !ok || v != x {
				return false
			}
		}

		return true
	}

	stats := map[Target]bool{}

	get_stats := func() map[Target]Counter {
		r := map[Target]Counter{}
		for v, _ := range stats {
			vr := vrpp{vip: v.VIP, rip: v.RIP, port: htons(v.Port), protocol: v.Protocol}
			co := counter{}
			xdp.BpfMapLookupElem(m.vrpp_counter(), uP(&vr), uP(&co))
			r[v] = Counter{Octets: co.octets, Packets: co.packets}
		}
		return r
	}

	go func() {

		type service struct {
			ip       [4]byte
			port     [2]byte
			protocol byte
			pad      byte
		}

		type backend struct {
			ip    [4]byte
			mac   [6]byte
			local [1]byte
			ps    [1]byte
			// could pack local/mode(l2,l3) flags in top 4 bits of a vlan field
		}

		defer close(done)

		//var old Report
		oldloc := map[uint16]backend{}
		oldmap := map[IP4]map[L4]map[[4]byte]uint16{}

		done := make(chan bool)

		for config := range ch {
			//fmt.Println("setting")

			close(done)
			done = make(chan bool)

			var all []IP4
			for _, b := range config.Backends {
				all = append(all, b.IP)
			}
			locals := find_local(all)

			for n, b := range config.Backends {

				s := backend{ip: b.IP, mac: b.MAC}

				if locals[b.IP] {
					//fmt.Println(b.IP, "IS LOCAL")
					s.local[0] = 1
				}

				var change bool

				if o, ok := oldloc[n]; ok {
					if o != s {
						change = true
					}
				} else {
					change = true
				}

				oldloc[n] = s

				if change {
					//fmt.Println("!!!!!!!!", n, s)
					r := xdp.BpfMapUpdateElem(m.backends(), uP(&n), uP(&s), xdp.BPF_ANY)

					if r != 0 {
						log.Fatal("backends", n, b)
					}
				}
			}

			for ip, _ := range oldmap {
				if _, ok := config.Virtuals[ip]; ok {
					// virtual IP exists still, check services
					for l4, _ := range oldmap[ip] {
						if _, ok := config.Virtuals[ip].Services[l4]; !ok {
							// service no longer exists - delete
							fmt.Println("deleteing", ip, l4)
							serv := service{ip: ip, port: htons(l4.Port), protocol: l4.Protocol.Number()}

							r := xdp.BpfMapDeleteElem(m.services(), uP(&serv))
							if r != 0 {
								log.Fatal("deleteing", ip, l4)
							}

						}
					}
				} else {
					// virtual IP no longer exists
					// remove all servces for this virtual IP

					fmt.Println("deleteing ...", ip)
					for l4, _ := range oldmap[ip] {
						fmt.Println("deleteing    ", ip, l4)
						serv := service{ip: ip, port: htons(l4.Port), protocol: l4.Protocol.Number()}
						r := xdp.BpfMapDeleteElem(m.services(), uP(&serv))
						if r != 0 {
							log.Fatal("deleteing", ip, l4)
						}
					}

					// remove catch-all drop for vip
					serv := service{ip: ip, port: htons(0)}
					bes, _ := rendezvous.RipIndex(map[[4]byte]uint16{})
					xdp.BpfMapUpdateElem(m.services(), uP(&serv), uP(&bes), xdp.BPF_ANY)

				}
			}

			newmap := map[IP4]map[L4]map[[4]byte]uint16{}

			for v, s := range config.Virtuals {

				newmap[v] = map[L4]map[[4]byte]uint16{}

				// catch-all drop for vip
				serv := service{ip: v, port: htons(0)}
				bes, _ := rendezvous.RipIndex(map[[4]byte]uint16{})
				xdp.BpfMapUpdateElem(m.services(), uP(&serv), uP(&bes), xdp.BPF_ANY)

				for l4, serv := range s.Services {

					foo := make(map[[4]byte]uint16)

					for n, up := range serv.Health {
						if be, ok := config.Backends[n]; up && ok {
							foo[be.IP] = uint16(n)
						}
					}

					for n, _ := range serv.Health {
						if be, ok := config.Backends[n]; ok {

							vip := v
							rip := be.IP
							port := l4.Port
							protocol := l4.Protocol.Number()

							vr := vrpp{vip: vip, rip: rip, port: htons(port), protocol: protocol}
							co := counter{}

							//r := xdp.BpfMapUpdateElem(m.vrpp_counter(), uP(&vr), uP(&co), xdp.BPF_ANY)
							xdp.BpfMapUpdateElem(m.vrpp_counter(), uP(&vr), uP(&co), xdp.BPF_NOEXIST)
							b := Target{VIP: vip, RIP: rip, Port: port, Protocol: protocol}
							stats[b] = true
						}
					}

					newmap[v][l4] = foo

					changed := true

					if oldmap != nil {
						if x, ok := oldmap[v]; ok {
							if y, ok := x[l4]; ok {
								if mapequ(y, foo) {
									changed = false
								}
							}
						}
					}

					if changed {
						sv := service{ip: v, port: htons(l4.Port), protocol: l4.Protocol.Number()}

						bes, stats := rendezvous.RipIndex(foo)

						fmt.Println("SETTING", v, l4, serv.Healthy)

						r := xdp.BpfMapUpdateElem(m.services(), uP(&sv), uP(&bes), xdp.BPF_ANY)

						if r != 0 {
							log.Fatal("services", v, l4)
						}

						fmt.Println(v, l4, sv, bes[0:64], stats)
					}
				}
			}

			oldmap = newmap
			//old = config
		}
	}()
	return ch, get_stats
}

func Foo(m *maps) {
	vip := [4]byte{192, 168, 101, 2}
	rip := [4]byte{192, 168, 0, 54}
	por := 8080
	pro := 6

	for {
		vr := vrpp{vip: vip, rip: rip, port: htons(uint16(por)), protocol: uint8(pro)}
		co := counter{}
		xdp.BpfMapLookupElem(m.vrpp_counter(), uP(&vr), uP(&co))

		fmt.Println("********************************************************************************", vr, co)
		time.Sleep(1 * time.Second)
	}
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
