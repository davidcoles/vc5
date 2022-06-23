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
	_ "embed"
	"fmt"
	"log"
	"net"
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

type Backend = healthchecks.Backend
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

type maps struct {
	m map[string]int
}

func Open(eth ...string) *maps {
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

	return &m
}

func (m *maps) backends() int { return m.m["backends"] }
func (m *maps) services() int { return m.m["services"] }

func (m *maps) nat_to_vip_mac() int { return m.m["nat_to_vip_mac"] }
func (m *maps) vip_mac_to_nat() int { return m.m["vip_mac_to_nat"] }

//func natstuff(m *maps, mp Mapping, done chan bool, bond, veth int, mac map[IP4]MAC, vc5aip, vc5bip IP4, vc5amac, vc5bmac MAC) chan Mapping {
func Natstuff(s1ip IP4, m *maps, h *Healthchecks, done chan bool, bond, veth int, mac map[IP4]MAC, vc5aip, vc5bip IP4, vc5amac, vc5bmac MAC) chan *Healthchecks {

	// nat -> vip + mac
	// mac + vip -> nat

	ch := make(chan *Healthchecks, 1)
	ch <- h

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

		type Mapping struct {
			Nat map[uint16]NAT
		}

		for h := range ch {
			defer close(done)

			for n, be := range h.Mappings {

				var nat [4]byte

				nat = Nat(n, vc5bip)
				vm := VM{vip: be.VIP, mac: be.MAC}

				srcmac := mac[s1ip]

				vme := VME{vip: be.VIP, mac: be.MAC, srcmac: srcmac, srcip: s1ip, ifindex: uint32(bond)}
				vm3 := VME{vip: vc5bip, mac: vc5bmac, srcip: nat, ifindex: uint32(veth)}

				if be.Loc {
					vme.ifindex = 0
					vm3.ifindex = 0
					vm.mac = vc5amac
				}

				xdp.BpfMapUpdateElem(m.nat_to_vip_mac(), uP(&nat), uP(&vme), xdp.BPF_ANY)
				xdp.BpfMapUpdateElem(m.vip_mac_to_nat(), uP(&vm), uP(&vm3), xdp.BPF_ANY)
			}
		}
	}()

	return ch
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

func Lbengine(m *maps, c Report, done chan bool) chan Report {
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

	go func() {

		type service struct {
			ip   [4]byte
			port [2]byte
			pad  [2]byte
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

		for config := range ch {
			fmt.Println("setting")

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
					fmt.Println("=============", n, s)
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
							serv := service{ip: ip, port: htons(l4.Port)}
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
						serv := service{ip: ip, port: htons(l4.Port)}
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
						sv := service{ip: v, port: htons(l4.Port)}

						bes, stats := rendezvous.RipIndex(foo)

						fmt.Println("setting", v, l4, serv.Healthy)

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
	return ch
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
