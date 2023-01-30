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
	//"fmt"
	"log"
	"net"
	"os"
	//"os/exec"
	"regexp"
	//"time"
	"unsafe"

	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/monitor"
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

type Status = monitor.Service
type Virtual = monitor.Virtual
type Report = monitor.Report

type maps = Maps
type Maps struct {
	m      map[string]int
	defcon uint8
}

type bpf_real struct {
	rip  [4]byte //__be32
	vid  [2]byte //__be16
	mac  [6]byte
	flag [4]byte
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
	new_flows      uint64
	dropped        uint64
}

type bpf_service struct {
	vip      [4]byte
	port     [2]byte
	protocol uint8
	pad      uint8
}

type bpf_backend struct {
	real [256]bpf_real
	hash [8192]byte
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
	ifindex uint32 //long bpf_redirect(u32 ifindex, u64 flags)
	vid     uint16
	pad     [2]byte
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
	Octets     uint64
	Packets    uint64
	Concurrent uint64
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
	//g.defcon = a.defcon
	g.new_flows += a.new_flows
}

func Open(bond string, native bool, vetha, vethb string, eth ...string) *Maps {
	var m maps
	m.m = make(map[string]int)
	m.defcon = 5

	//x, err := xdp.LoadBpfFile_(BPF_O, "xdp_main", native, bond, vetha, vethb, eth...)
	x, err := xdp.LoadBpfFile_(BPF_O, "incoming", "outgoing", native, bond, vetha, vethb, eth...)

	if err != nil {
		log.Fatal(err)
	}

	// balancer
	m.m["service_backend"] = find_map(x, "service_backend", 8, (256*16)+8192)

	// nat
	m.m["nat_to_vip_mac"] = find_map(x, "nat_to_vip_mac", 4, 28)
	m.m["vip_mac_to_nat"] = find_map(x, "vip_mac_to_nat", 10, 28)

	// stats
	m.m["globals"] = find_map(x, "globals", 4, 64)
	m.m["vrpp_counter"] = find_map(x, "vrpp_counter", 12, 16)
	m.m["vrpp_concurrent"] = find_map(x, "vrpp_concurrent", 12, 8)

	// control
	m.m["settings"] = find_map(x, "settings", 4, 2)

	var zero uint32
	s := bpf_setting{defcon: m.defcon, era: 0}

	if xdp.BpfMapUpdateElem(m.settings(), uP(&zero), uP(&s), xdp.BPF_ANY) != 0 {
		panic("oops")
	}

	return &m
}

func (m *maps) service_backend() int { return m.m["service_backend"] }
func (m *maps) nat_to_vip_mac() int  { return m.m["nat_to_vip_mac"] }
func (m *maps) vip_mac_to_nat() int  { return m.m["vip_mac_to_nat"] }
func (m *maps) vrpp_counter() int    { return m.m["vrpp_counter"] }
func (m *maps) vrpp_concurrent() int { return m.m["vrpp_concurrent"] }
func (m *maps) globals() int         { return m.m["globals"] }
func (m *maps) settings() int        { return m.m["settings"] }

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

func (m *maps) update_vrpp_concurrent(v *bpf_vrpp, c *int64, flag uint64) int {

	all := make([]int64, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		if c == nil {
			all[n] = 0
		} else {
			all[n] = *c
		}
	}

	return xdp.BpfMapUpdateElem(m.vrpp_concurrent(), uP(v), uP(&(all[0])), flag)
}

func (m *maps) lookup_vrpp_concurrent(v *bpf_vrpp, c *int64) int {

	co := make([]int64, xdp.BpfNumPossibleCpus())

	ret := xdp.BpfMapLookupElem(m.vrpp_concurrent(), uP(v), uP(&(co[0])))

	var x int64

	for _, v := range co {
		x += v
	}

	*c = x

	return ret
}

func (m *maps) GlobalStats() (uint64, uint64, uint64, uint64, uint8) {
	var g bpf_global
	m.lookup_globals(&g)

	var latency uint64
	if g.packets > 0 {
		latency = g.timens / g.packets
	}

	//return g.rx_packets, g.rx_octets, latency, uint8(g.defcon)
	return g.rx_packets, g.rx_octets, g.new_flows, latency, m.defcon
}

func (m *maps) DEFCON(d uint8) uint8 {

	var zero uint32
	var s bpf_setting

	if d <= 5 {
		m.defcon = d
		s.defcon = m.defcon

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

func Nat(n uint16, ip IP4) [4]byte {
	hl := htons(n)
	var nat [4]byte
	nat[0] = ip[0]
	nat[1] = ip[1]
	nat[2] = hl[0]
	nat[3] = hl[1]
	return nat
}

func find_map(x *xdp.XDP, name string, ks int, rs int) int {
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

/*
func _ping(ip IP4) chan bool {
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
*/
