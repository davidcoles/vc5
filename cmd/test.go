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
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"time"
	"unsafe"

	"github.com/davidcoles/vc5/rendezvous"
	"github.com/davidcoles/vc5/types"
	"github.com/davidcoles/vc5/xdp"
)

type uP = unsafe.Pointer
type IP4 = types.IP4
type MAC = types.MAC
type L4 = types.L4
type Protocol = types.Protocol

const TCP = types.TCP
const UDP = types.UDP

//go:embed test_o
var TEST_O []byte

type Config struct {
	Virtuals  map[IP4]map[uint16][]uint16
	Backends  map[uint16]Backend
	Advertise []IP4
}

// nat -> vip + mac
// mac + vip -> nat
type Mapping struct {
	Nat map[uint16]NAT
}

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

func htons(p uint16) [2]byte {
	var hl [2]byte
	hl[0] = byte(p >> 8)
	hl[1] = byte(p & 0xff)
	return hl
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

var s1ip [4]byte = [4]byte{192, 168, 0, 54}

var locals map[IP4]bool = map[IP4]bool{s1ip: true}

func loadConfigFile(file string) (*Healthchecks, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var config Healthchecks

	err = json.Unmarshal(b, &(config))
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func main() {

	bond := os.Args[1]
	vc5a := "vc5a"
	vc5b := "vc5b"

	var eth []string
	eth = append(eth, vc5a)
	eth = append(eth, vc5b)
	eth = append(eth, os.Args[2:]...)

	setup1(vc5a, vc5b)

	var vc5amac [6]byte
	var vc5bmac [6]byte

	iface, err := net.InterfaceByName(bond)
	if err != nil {
		log.Fatal(err)
	}
	//bondidx := iface.Index

	iface, err = net.InterfaceByName(vc5a)
	if err != nil {
		log.Fatal(err)
	}
	copy(vc5amac[:], iface.HardwareAddr[:])

	//vc5aidx := iface.Index

	iface, err = net.InterfaceByName(vc5b)
	if err != nil {
		log.Fatal(err)
	}
	copy(vc5bmac[:], iface.HardwareAddr[:])

	m := open(eth...)

	rules(m)

	/*

		var vc5aip [4]byte = [4]byte{10, 255, 255, 253}
		var vc5bip [4]byte = [4]byte{10, 255, 255, 254}

		setup2("vc5", vc5a, vc5b, vc5aip, vc5bip)

		done1 := make(chan bool)
		done2 := make(chan bool)

		n := nat(m, mapping, done1, bondidx, vc5aidx, mac, vc5aip, vc5bip, vc5amac, vc5bmac)
		c := lbengine(m, config, done2)

		time.Sleep(2 * time.Second)

		delete(config.Virtuals[vip1], 80)
		delete(config.Virtuals, vip2)

		c <- config

		time.Sleep(2 * time.Second)

		close(c)
		close(n)

		<-done1
		<-done2
	*/
}

type Reals map[uint16]Real
type Real struct {
	NAT uint16
	RIP IP4
}

type Healthchecks struct {
	Virtuals map[IP4]map[L4]Reals
	Backends map[uint16]IP4
	Mapping  map[uint16][2]IP4
}

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

func rules(m *maps) {

	var TCP80 L4 = L4{Protocol: TCP, Port: 8080}
	//var vip1 [4]byte = [4]byte{192, 168, 101, 2}
	var vip2 [4]byte = [4]byte{192, 168, 101, 3}
	//var s1ip [4]byte = [4]byte{192, 168, 0, 54}
	//var s2ip [4]byte = [4]byte{192, 168, 0, 8}
	//var s3ip [4]byte = [4]byte{192, 168, 0, 3}
	/*
		var h Healthchecks
		h.Virtuals = map[IP4]map[L4]Reals{}
		h.Virtuals[vip1] = map[L4]Reals{}
		h.Virtuals[vip2] = map[L4]Reals{}
		h.Virtuals[vip1][TCP80] = Reals{1: Real{RIP: s1ip, NAT: 1}, 2: Real{RIP: s2ip, NAT: 2}}
		h.Virtuals[vip2][TCP80] = Reals{1: Real{RIP: s1ip, NAT: 1}}

		h.Backends = map[uint16]IP4{1: s1ip, 2: s2ip, 3: s3ip}

		h.Mapping = map[uint16][2]IP4{
			1: [2]IP4{vip1, s1ip},
			2: [2]IP4{vip1, s2ip},
			3: [2]IP4{vip1, s3ip},
			4: [2]IP4{vip2, s3ip},
		}
	*/
	hp, err := loadConfigFile("cmd/test.json")
	if err != nil {
		panic(err)
	}
	h := *hp

	j, _ := json.MarshalIndent(&h, "", "  ")
	fmt.Println(string(j))

	time.Sleep(3 * time.Second)

	done := make(chan bool)
	fn := monitor(h)
	cf := fn(nil, false)
	lb := lbengine(m, cf, done)

	time.Sleep(3 * time.Second)
	lb <- dump(fn(&h, false))

	time.Sleep(3 * time.Second)
	delete(h.Virtuals[vip2], TCP80)
	cf = dump(fn(&h, false))
	lb <- cf

	time.Sleep(3 * time.Second)

	close(lb)

	<-done
}

type context struct {
	vip IP4
	l4  L4
}

type Status struct {
	//Metadata Metadata
	Health  map[uint16]bool `json:"health"`
	Healthy bool            `json:"healthy"`
}

type Virtual struct {
	Services map[L4]Status
	Metadata Metadata
	Healthy  bool
}

type Report struct {
	Virtuals map[IP4]Virtual //map[IP4]map[L4]Status
	Backends map[uint16]Backend
}

type Metadata struct {
	Name        string
	Description string
}

//func monitor(h Healthchecks) func(*Healthchecks, bool) map[IP4]map[uint16]Status {
func monitor(h Healthchecks) func(*Healthchecks, bool) Report {

	x := map[IP4]func(*(map[L4]Reals), bool) map[L4]Status{}
	backends := map[uint16]IP4{}

	update := func(h *Healthchecks, fin bool) {

		if h != nil {

			backends = h.Backends

			for vip, services := range h.Virtuals {
				if fn, ok := x[vip]; ok {
					fn(&services, false) // update sub-tree
				} else {
					x[vip] = virtual(&services, context{vip: vip})
				}
			}

			for k, fn := range x {
				if _, ok := h.Virtuals[k]; !ok {
					fn(nil, true)
					delete(x, k)
				}
			}
		}

		if fin {
			for k, fn := range x {
				fn(nil, true)
				delete(x, k)
			}
		}
	}

	update(&h, false)

	return func(h *Healthchecks, fin bool) Report {
		update(h, false)

		var r Report

		r.Virtuals = map[IP4]Virtual{}
		for k, fn := range x {
			v := Virtual{Healthy: true}
			v.Services = fn(nil, false)
			r.Virtuals[k] = v
			for _, s := range v.Services {
				if !s.Healthy {
					v.Healthy = false
				}
			}
		}

		all := []IP4{}

		for _, v := range backends {
			all = append(all, v)
		}

		m := macs(all)

		r.Backends = map[uint16]Backend{}
		for k, v := range backends {

			r.Backends[k] = Backend{IP: v, MAC: m[v]}
		}

		update(nil, fin)

		return r
	}
}

func virtual(services *map[L4]Reals, c context) func(*(map[L4]Reals), bool) map[L4]Status {

	x := map[L4]func(*Reals, bool) Status{}

	update := func(services *(map[L4]Reals), fin bool) {
		if services != nil {
			for s, v := range *services {
				if _, ok := x[s]; ok {
					x[s](&v, false)
				} else {
					x[s] = service_(&v, context{vip: c.vip, l4: s})
				}
			}

			for s, fn := range x {
				if _, ok := (*services)[s]; !ok {
					fn(nil, true)
					delete(x, s)
				}
			}
		}

		if fin {
			for k, fn := range x {
				fn(nil, true)
				delete(x, k)
			}
		}
	}

	update(services, false)

	return func(services *(map[L4]Reals), fin bool) map[L4]Status {

		update(services, false)

		y := map[L4]Status{}
		for k, fn := range x {
			y[k] = fn(nil, false)
		}

		update(nil, fin)

		return y
	}
}

func service_(service *Reals, c context) func(*Reals, bool) Status {

	x := map[uint16]func(*Real, bool) bool{}

	update := func(reals *Reals, fin bool) {
		if reals != nil {

			for real, r := range *reals {
				if _, ok := x[real]; ok {
					x[real](&r, false)
				} else {
					x[real] = rip(&r, c)
				}
			}

			for real, fn := range x {
				if _, ok := (*reals)[real]; !ok {
					fn(nil, true)
					delete(x, real)
				}
			}
		}

		if fin {
			for k, fn := range x {
				fn(nil, fin)
				delete(x, k)
			}
		}
	}

	update(service, false)

	return func(service *Reals, fin bool) Status {
		update(service, false)

		status := Status{Health: map[uint16]bool{}}
		var healthy uint16

		for k, v := range x {
			b := v(nil, false)

			if b {
				healthy++
			}

			status.Health[k] = b
		}

		if healthy > 0 {
			status.Healthy = true
		}

		update(nil, fin)

		return status
	}
}

func rip(r *Real, c context) func(*Real, bool) bool {

	x := *r

	var up bool

	done := make(chan bool)
	go foobar(done, &up, x.RIP)
	fmt.Println(c, r.RIP)

	return func(ip *Real, fin bool) bool {
		if fin {
			close(done)
		}

		return up
	}
}

func foobar(d chan bool, up *bool, x IP4) {
	for {
		select {
		case <-time.After(1 * time.Second):
			//fmt.Println("WAIT", x)
			*up = true
		case <-d:
			//fmt.Println("DONE", x)
			return
		}
	}
}

func lbengine(m *maps, c Report, done chan bool) chan Report {

	ch := make(chan Report, 1)
	ch <- c

	go func() {

		defer close(done)

		var old Report

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
					fmt.Println(b.IP, "IS LOCAL")
					s.local[0] = 1
				}

				r := xdp.BpfMapUpdateElem(m.backends(), uP(&n), uP(&s), xdp.BPF_ANY)

				if r != 0 {
					log.Fatal("backends", n, b)
				}

			}

			if old.Virtuals != nil {
				for ip, _ := range old.Virtuals {
					if _, ok := config.Virtuals[ip]; ok {
						// virtual IP exists still, check services
						for l4, _ := range old.Virtuals[ip].Services {
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
						for port, _ := range old.Virtuals[ip].Services {
							fmt.Println("deleteing    ", ip, port)
							serv := service{ip: ip, port: htons(port.Port)}
							r := xdp.BpfMapDeleteElem(m.services(), uP(&serv))
							if r != 0 {
								log.Fatal("deleteing", ip, port)
							}
						}

						// remove catch-all drop for vip
						serv := service{ip: ip, port: htons(0)}
						bes, _ := rendezvous.RipIndex(map[[4]byte]uint16{})
						xdp.BpfMapUpdateElem(m.services(), uP(&serv), uP(&bes), xdp.BPF_ANY)

					}
				}
			}

			for v, s := range config.Virtuals {

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

					sv := service{ip: v, port: htons(l4.Port)}

					bes, _ := rendezvous.RipIndex(foo)

					fmt.Println("setting", v, l4, serv.Healthy)

					r := xdp.BpfMapUpdateElem(m.services(), uP(&sv), uP(&bes), xdp.BPF_ANY)

					if r != 0 {
						log.Fatal("services", v, l4)
					}

					//fmt.Println(bes[0:32], stats)
				}
			}

			old = config
		}
	}()
	return ch
}

/**********************************************************************/

type Backend struct {
	MAC MAC
	IP  IP4
}

type NAT struct {
	MAC MAC
	VIP IP4
	RIP IP4
}

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

func nat(m *maps, mp Mapping, done chan bool, bond, veth int, mac map[IP4]MAC, vc5aip, vc5bip IP4, vc5amac, vc5bmac MAC) chan Mapping {
	ch := make(chan Mapping, 1)
	ch <- mp

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

		for mp := range ch {
			defer close(done)

			var all []IP4
			for _, b := range mp.Nat {
				all = append(all, b.RIP)
			}
			locals := find_local(all)

			//fmt.Println("=============", locals)

			for n, be := range mp.Nat {

				var nat [4]byte

				nat = Nat(n)
				vm := VM{vip: be.VIP, mac: be.MAC}

				srcmac := mac[s1ip]

				vme := VME{vip: be.VIP, mac: be.MAC, srcmac: srcmac, srcip: s1ip, ifindex: uint32(bond)}
				vm3 := VME{vip: vc5bip, mac: vc5bmac, srcip: nat, ifindex: uint32(veth)}

				if locals[be.RIP] {
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
