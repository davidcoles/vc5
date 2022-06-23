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

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"time"
	"unsafe"

	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/types"
	//"github.com/davidcoles/vc5/rendezvous"
	//"github.com/davidcoles/vc5/xdp"
)

type uP = unsafe.Pointer
type IP4 = types.IP4
type MAC = types.MAC
type L4 = types.L4

//type Protocol = types.Protocol

type Config struct {
	Virtuals  map[IP4]map[uint16][]uint16
	Backends  map[uint16]Backend
	Advertise []IP4
}

var s1ip [4]byte = [4]byte{192, 168, 0, 54}

var locals map[IP4]bool = map[IP4]bool{s1ip: true}

func main() {

	file := os.Args[1]
	bond := os.Args[2]
	vc5a := "vc5a"
	vc5b := "vc5b"

	var eth []string
	eth = append(eth, vc5a)
	eth = append(eth, vc5b)
	eth = append(eth, os.Args[3:]...)

	conf, err := config2.Load(file, nil)
	rips := conf.RIPs()
	nats := conf.NATs()

	if err != nil {
		log.Fatal(err)
	}

	setup1(vc5a, vc5b)

	var vc5amac [6]byte
	var vc5bmac [6]byte

	iface, err := net.InterfaceByName(bond)
	if err != nil {
		log.Fatal(err)
	}
	bondidx := iface.Index

	iface, err = net.InterfaceByName(vc5a)
	if err != nil {
		log.Fatal(err)
	}
	copy(vc5amac[:], iface.HardwareAddr[:])

	vc5aidx := iface.Index

	iface, err = net.InterfaceByName(vc5b)
	if err != nil {
		log.Fatal(err)
	}
	copy(vc5bmac[:], iface.HardwareAddr[:])

	m := kernel.Open(eth...)

	fmt.Println(rips, nats, bondidx, vc5aidx)

	var ips []IP4
	for _, v := range rips {
		ips = append(ips, v)
	}

	mac := macs(ips)
	loc := find_local(ips)

	fmt.Println(m)

	var vc5aip [4]byte = [4]byte{10, 255, 255, 253}
	var vc5bip [4]byte = [4]byte{10, 255, 255, 254}

	setup2("vc5", vc5a, vc5b, vc5aip, vc5bip)

	done := make(chan bool)

	hc, _ := healthchecks.ConfHealthchecks(conf)

	//hc, _ := confHealthchecks(conf)

	hc.Mappings = map[uint16]NAT{}

	for k, v := range hc.Mapping {
		hc.Mappings[k] = NAT{VIP: v[0], RIP: v[1], MAC: mac[v[1]], Loc: loc[v[1]]}
	}

	j, _ := json.MarshalIndent(&hc, "", "  ")
	fmt.Println(string(j))

	ns := kernel.Natstuff(s1ip, m, hc, done, bondidx, vc5aidx, mac, vc5aip, vc5bip, vc5amac, vc5bmac)

	time.Sleep(2 * time.Second)

	defer func() {
		close(ns)
		<-done
	}()

	done2 := make(chan bool)
	fn := monitor.Monitor(hc)

	time.Sleep(5 * time.Second)

	cf := fn(nil, false)
	j, _ = json.MarshalIndent(cf, "", "  ")
	fmt.Println(string(j))

	lb := kernel.Lbengine(m, cf, done2)

	for {

		lb <- fn(nil, false)

		time.Sleep(30 * time.Second)

		delete(hc.Virtuals[[4]byte{192, 168, 101, 3}].Services[L4{Protocol: false, Port: 8080}].Reals, 2)

		fn(hc, false)
	}

	close(lb)

	<-done2
}

type Backend = healthchecks.Backend
type Healthchecks = healthchecks.Healthchecks
type NAT = healthchecks.NAT
type Report = monitor.Report

func dump(r Report) Report {
	j, _ := json.MarshalIndent(&r, "", "  ")
	var g bytes.Buffer
	w := gzip.NewWriter(&g)
	w.Write(j)
	w.Close()
	b := base64.StdEncoding.EncodeToString(g.Bytes())
	fmt.Println(b, string(j))
	return r
}

type context struct {
	vip IP4
	l4  L4
}

/**********************************************************************/

func setup1(if1, if2 string) {
	script1 := `
ip link del ` + if1 + ` >/dev/null 2>&1 || true
ip link add ` + if1 + ` type veth peer name ` + if2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		log.Fatal(err)
	}
}

func setup2(ns, if1, if2 string, i1, i2 IP4) {
	ip1 := i1.String()
	ip2 := i2.String()
	cb := i1
	cb[2] = 0
	cb[3] = 0
	cbs := cb.String()

	script1 := `
ip netns del ` + ns + ` >/dev/null 2>&1 || true
ip l set ` + if1 + ` up
ip a add ` + ip1 + `/30 dev ` + if1 + `
ip netns add ` + ns + `
ip link set ` + if2 + ` netns ` + ns + `
ip netns exec vc5 /bin/sh -c "ip l set ` + if2 + ` up && ip a add ` + ip2 + `/30 dev ` + if2 + ` && ip r replace default via ` + ip1 + ` && ip netns exec ` + ns + ` ethtool -K ` + if2 + ` tx off"
ip r replace ` + cbs + `/16 via ` + ip2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		log.Fatal(err)
	}
}

func read_macs(rip map[IP4]bool) (map[IP4]MAC, error) {

	ip2mac := make(map[IP4]MAC)
	ip2nic := make(map[IP4]*net.Interface)

	re := regexp.MustCompile(`^(\S+)\s+0x1\s+0x.\s+(\S+)\s+\S+\s+(\S+)$`)

	file, err := os.OpenFile("/proc/net/arp", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
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

			if _, ok := rip[ip4]; !ok {
				continue
			}

			ip2mac[ip4] = mac
			ip2nic[ip4] = iface
		}
	}

	return ip2mac, nil
}

func macs(ips []IP4) map[IP4]MAC {
	locals := map[IP4]bool{}
	hwaddr := map[IP4]MAC{}

	for _, v := range ips {
		locals[v] = false
	}

	for k, _ := range locals {
		hwaddr[k] = MAC{}
	}

	ifaces, err := net.Interfaces()

	if err == nil {

		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				log.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
				continue
			}
			for _, a := range addrs {

				ip, _, err := net.ParseCIDR(a.String())

				if err == nil {

					ip4 := ip.To4()

					if ip4 != nil {
						x := IP4{ip4[0], ip4[1], ip4[2], ip4[3]}

						if _, ok := locals[x]; ok {
							locals[x] = true
							var mac MAC
							copy(mac[:], i.HardwareAddr)
							hwaddr[x] = mac
						}
					}
				}
			}
		}
	}

	remote := map[IP4]bool{}

	for k, v := range locals {
		if !v {
			remote[k] = true
		}
	}

	r, err := read_macs(remote)

	if err == nil {
		for k, v := range r {
			hwaddr[k] = v
		}
	}

	return hwaddr
}

/*
func (r *RIP) xChecks() Checks {
	var c Checks
	c.Http = r.Http
	c.Https = r.Https
	c.Tcp = r.Tcp
	c.Syn = r.Syn
	c.Dns = r.Dns
	return c
}
*/
/*
type xServ struct {
	Name        string
	Description string
	Need        uint16
	Leastconns  bool
	Sticky      bool
	RIPs        map[IP4]RIP
}
*/

/*
type xRIP struct {
	Http  []Check `json:"http,omitempty"`
	Https []Check `json:"https,omitempty"`
	Tcp   []Check `json:"tcp,omitempty"`
	Syn   []Check `json:"syn,omitempty"`
	Dns   []Check `json:"dns,omitempty"`
}
*/
/*
type maps struct {
	m map[string]int
}

func open(eth ...string) *maps {
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
func natstuff(m *maps, h *Healthchecks, done chan bool, bond, veth int, mac map[IP4]MAC, vc5aip, vc5bip IP4, vc5amac, vc5bmac MAC) chan *Healthchecks {

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

				nat = Nat(n)
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

func Nat(n uint16) [4]byte {
	hl := htons(n)
	var nat [4]byte
	nat[0] = 10
	nat[1] = 255
	nat[2] = hl[0]
	nat[3] = hl[1]
	return nat
}

func lbengine(m *maps, c Report, done chan bool) chan Report {
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
*/
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
