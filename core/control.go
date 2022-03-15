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

package core

import (
	_ "embed"
	"fmt"
	"log"
	"net"
	//"os/exec"
	"time"
	"unsafe"

	"github.com/davidcoles/vc5/types"
	"github.com/davidcoles/vc5/xdp"
)

//go:embed bpf/simple.o
var SIMPLE_O []byte

//go:embed bpf/bpf.o
var BPF_O []byte

type counters = types.Counters

type IP4 = types.IP4
type IP6 = types.IP6
type MAC = types.MAC
type uP = unsafe.Pointer

type raw_counters struct {
	new_flows  uint64 //`json:"total_connections"`
	rx_packets uint64 //`json:"rx_packets"`
	rx_bytes   uint64 //`json:"rx_bytes"`
	fp_count   uint64
	fp_time    uint64
	qfailed    uint64
}

func (r raw_counters) cook() counters {
	var c counters
	c.New_flows = r.new_flows
	c.Rx_packets = r.rx_packets
	c.Rx_bytes = r.rx_bytes
	c.Fp_count = r.fp_count
	c.Fp_time = r.fp_time
	c.Qfailed = r.qfailed
	return c
}

func (c *raw_counters) add(r raw_counters) {
	c.new_flows += r.new_flows
	c.rx_packets += r.rx_packets
	c.rx_bytes += r.rx_bytes
	c.fp_count += r.fp_count
	c.fp_time += r.fp_time
	c.qfailed += r.qfailed
}

const FLOW = 12
const STATE = 32
const FLOW_STATE = FLOW + STATE
const MAX_CPU = 32
const INTERVAL = 5

type Control struct {
	xdp      *xdp.XDP_
	era      uint64
	interval uint8
	defcon   uint8

	settings                int
	interfaces              int
	service_backend         int
	rip_to_mac              int
	mac_to_rip              int
	nat_to_vip_rip          int
	vip_rip_to_nat          int
	clocks                  int
	vip_rip_port_counters   int
	vip_rip_port_concurrent int
	stats                   int
	flow_queue              int
	flows                   int
	backend_recs            int
	backend_idx             int
	tx_port                 int

	//// logger *logger
	//iface2u8 map[string]uint8

	//ipaddr IP4
	//hwaddr  MAC
	//ifindex uint32
}

func (c *Control) Era() (uint64, uint8) {
	return c.era, c.interval
}

//func (c *Control) IPAddr() [4]byte {
//	return c.ipaddr
//}

type service struct {
	vip   IP4
	port  [2]byte
	proto byte
	pad   byte
}

type tuple struct {
	src      IP4
	dst      IP4
	sport    uint16
	dport    uint16
	protocol byte
	padding  [3]byte
}

type vip_rip_src_if struct {
	vip     IP4
	rip     IP4
	src     IP4
	ifindex uint32
	hwaddr  MAC
	vlan_hi byte
	vlan_lo byte
}

type interfaces struct {
	ifindex uint32
	ipaddr  IP4
	hwaddr  [6]byte
	padding [2]byte
}

func (c *Control) find_map(name string, ks int, rs int) int {
	m := c.xdp.FindMap(name)

	if m == -1 {
		log.Fatal(name, "not found")
	}

	if !c.xdp.CheckMap(m, ks, rs) {
		log.Fatal(name, " incorrect size")
	}

	return m
}

func (c *Control) Defcon(d uint8) uint8 {
	if d != 0 {
		c.defcon = d
	}
	return c.defcon
}

func (c *Control) global_update() {
	var zero uint32 = 0
	c.era = 0

	type settings struct {
		era    uint64  //__u64 era;
		time   uint64  //__u64 time;
		pad    [7]byte //__u8 pad[7];
		defcon uint8   //__u8 defcon;
	}

	go func() {
		for {
			var s settings
			s.defcon = c.defcon
			var settings [MAX_CPU]settings
			for i, _ := range settings {
				settings[i] = s
			}
			xdp.BpfMapUpdateElem(c.settings, uP(&zero), uP(&settings), xdp.BPF_ANY)
			time.Sleep(1 * time.Second)
		}
	}()

	type clocks struct {
		era    uint64
		time   uint64
		defcon uint8
		pad    [7]byte
	}

	var clock clocks
	clock.defcon = 1

	go func() {
		for {
			clock.time = uint64(time.Now().Unix())
			xdp.BpfMapUpdateElem(c.clocks, uP(&zero), uP(&clock), xdp.BPF_ANY)
			time.Sleep(1 * time.Second)
		}
	}()

	for {
		c.era++
		clock.era = c.era
		xdp.BpfMapUpdateElem(c.clocks, uP(&zero), uP(&clock), xdp.BPF_ANY)
		time.Sleep(INTERVAL * time.Second)
	}

}

func New(bpf []byte, ipaddr IP4, veth string, vip IP4, hwaddr [6]byte, native, bridge bool, peth ...string) *Control {

	var c Control

	c.interval = INTERVAL
	//c.ipaddr = ipaddr
	////c.logger = NewLogger()

	prog := "xdp_main"

	if bridge {
		prog = "xdp_main_bridge"
	}

	x, e := xdp.LoadBpfFile(veth, bpf, prog, native, peth...)

	if e != nil {
		log.Fatal(e)
	}

	c.xdp = x
	c.defcon = 5

	c.settings = c.find_map("settings", 4, 24)
	c.interfaces = c.find_map("interfaces", 4, 16)
	//c.service_backend = c.find_map("service_backend", 8, 65536*12+12+1)
	c.rip_to_mac = c.find_map("rip_to_mac", 4, 6)
	c.mac_to_rip = c.find_map("mac_to_rip", 6, 4)
	c.nat_to_vip_rip = c.find_map("nat_to_vip_rip", 4, 24)
	c.vip_rip_to_nat = c.find_map("vip_rip_to_nat", 8, 4)
	c.clocks = c.find_map("clocks", 4, 24)
	c.vip_rip_port_counters = c.find_map("vip_rip_port_counters", 12, 8*6)
	c.vip_rip_port_concurrent = c.find_map("vip_rip_port_concurrent", 12, 4)
	c.stats = c.find_map("stats", 4, 8*6)
	c.flow_queue = c.find_map("flow_queue", 0, FLOW_STATE)
	c.flows = c.find_map("flows", FLOW, STATE)
	c.backend_recs = c.find_map("backend_recs", 4, 16)
	c.backend_idx = c.find_map("backend_idx", 8, 8192)
	c.tx_port = c.find_map("tx_port", 4, 4)

	//if p, err := net.InterfaceByName(peth[0]); err != nil {
	//	fmt.Println(peth, err)
	//	return nil
	//} else {
	//	//c.ifindex = uint32(p.Index)
	//	//copy(c.hwaddr[:], p.HardwareAddr[:])
	//}

	if v, err := net.InterfaceByName(veth); err != nil {
		fmt.Println(veth, err)
		return nil
	} else {
		var zero uint32
		var virt interfaces
		virt.ifindex = uint32(v.Index)
		virt.ipaddr = vip
		virt.hwaddr = hwaddr
		xdp.BpfMapUpdateElem(c.interfaces, uP(&zero), uP(&virt), xdp.BPF_ANY)
	}

	/*
		for i, n := range nics {
			var k int32 = int32(i)
			var v int32 = int32(n.Iface.Index)
			xdp.BpfMapUpdateElem(c.tx_port, uP(&k), uP(&v), xdp.BPF_ANY)
		}
	*/

	go c.global_update()

	return &c
}

//nat->vip/rip
//vip/rip->nat

func (c *Control) SetBackendRec(rip IP4, mac MAC, vlan uint16, idx uint16, tx uint8) {
	type rec = [16]byte
	i := uint32(idx)

	//r := rec{mac: mac, vlan: vlan, rip: rip}
	var r rec
	copy(r[0:], mac[:])
	copy(r[8:], rip[:])
	r[12] = tx

	r[6] = byte((vlan >> 8) & 0xff)
	r[7] = byte(vlan & 0xff)

	var recs [MAX_CPU * 16]byte

	for n := 0; n < MAX_CPU; n++ {
		copy(recs[(n*16):], r[:])
	}

	//fmt.Println("SETBACKENDREC", rip, mac, vlan, idx)

	if xdp.BpfMapUpdateElem(c.backend_recs, uP(&i), uP(&recs), xdp.BPF_ANY) != 0 {
		panic("c.backend_recs")
	}
}

func (c *Control) SetBackendIdx(vip IP4, port uint16, udp bool, idx [8192]uint8) {
	var s service
	s.vip = vip
	s.port[0] = byte((port >> 8) & 0xff)
	s.port[1] = byte(port & 0xff)
	if udp {
		s.proto = 1
	}

	var idxs [MAX_CPU][8192]uint8

	for n := 0; n < len(idxs); n++ {
		idxs[n] = idx
	}
	//fmt.Println("SETBACKENDIDX", vip, port, idx[0:32])
	if xdp.BpfMapUpdateElem(c.backend_idx, uP(&s), uP(&idxs), xdp.BPF_ANY) != 0 {
		panic("c.backend_idx")
	}
}
func (c *Control) DelBackendIdx(vip IP4, port uint16, udp bool) {
	var s service
	s.vip = vip
	s.port[0] = byte((port >> 8) & 0xff)
	s.port[1] = byte(port & 0xff)
	if udp {
		s.proto = 1
	}

	xdp.BpfMapDeleteElem(c.backend_idx, uP(&s))
}

func (c *Control) DelNatVipRip(nat, vip, rip IP4) {
	vr := vip_rip_src_if{vip: vip, rip: rip}
	xdp.BpfMapLookupAndDeleteElem(c.vip_rip_to_nat, uP(&vr), uP(&nat))
	xdp.BpfMapLookupAndDeleteElem(c.nat_to_vip_rip, uP(&nat), uP(&vr))
}
func (c *Control) SetNatVipRip(nat, vip, rip, src IP4, iface string, vlan uint16, ifindex_ int, ifhw MAC) {

	ifindex := uint32(ifindex_)
	ipaddr := src
	hwaddr := ifhw

	vr := vip_rip_src_if{vip: vip, rip: rip, src: ipaddr, ifindex: ifindex, hwaddr: hwaddr, vlan_hi: byte(vlan >> 8), vlan_lo: byte(vlan & 0xff)}
	//fmt.Println("SETNATVIPRIP", nat, vip, rip, src, iface, vlan, ifindex_, ifhw)

	xdp.BpfMapUpdateElem(c.nat_to_vip_rip, uP(&nat), uP(&vr), xdp.BPF_ANY)
	xdp.BpfMapUpdateElem(c.vip_rip_to_nat, uP(&vr), uP(&nat), xdp.BPF_ANY)

}

func (c *Control) SetRip(rip IP4) {
	var mac MAC
	//fmt.Println("SETRIP", rip)
	xdp.BpfMapUpdateElem(c.rip_to_mac, uP(&rip), uP(&mac), xdp.BPF_ANY)
	//go ping(rip)
}

func (c *Control) SetRipMac(rip IP4, mac MAC) {
	xdp.BpfMapUpdateElem(c.rip_to_mac, uP(&rip), uP(&mac), xdp.BPF_ANY)

	var nul MAC
	if mac != nul {
		xdp.BpfMapUpdateElem(c.mac_to_rip, uP(&mac), uP(&rip), xdp.BPF_ANY)
	}
}
func (c *Control) DelMac(mac MAC) {
	xdp.BpfMapDeleteElem(c.mac_to_rip, uP(&mac))
}
func (c *Control) DelRip(rip IP4) {
	xdp.BpfMapDeleteElem(c.rip_to_mac, uP(&rip))
}

func (c *Control) _SetBackends(vip IP4, port uint16, backends [65536][12]byte, least [12]byte, weight byte) {
	if false {
		var s service
		s.vip = vip
		s.port[0] = byte((port >> 8) & 0xff)
		s.port[1] = byte(port & 0xff)

		type bes struct {
			backends [65536][12]byte
			least    [12]byte
			weight   byte
		}

		be := bes{backends: backends, least: least, weight: weight}
		xdp.BpfMapUpdateElem(c.service_backend, uP(&s), uP(&be), xdp.BPF_ANY)
	}
}

func (c *Control) ReadMAC(ip IP4) *MAC {
	var m MAC
	if xdp.BpfMapLookupElem(c.rip_to_mac, uP(&ip), uP(&m)) != 0 {
		return nil
	}

	cmpmac := func(a, b [6]byte) int {
		for n := 0; n < len(a); n++ {
			if a[n] < b[n] {
				return -1
			}
			if a[n] > b[n] {
				return 1
			}
		}
		return 0
	}

	if cmpmac(m, [6]byte{0, 0, 0, 0, 0, 0}) == 0 {
		return nil
	}

	return &m
}

//func ping(ip IP4) {
//	command := fmt.Sprintf("ping -n -c 1 -w 1  %d.%d.%d.%d >/dev/null 2>&1", ip[0], ip[1], ip[2], ip[3])
//	exec.Command("/bin/sh", "-c", command).Output()
//}

func (c *Control) VipRipPortCounters2(vip, rip IP4, port uint16, clear bool, curr uint64) counters {
	count := c.VipRipPortCounters(vip, rip, port, clear)
	count.Concurrent = int64(curr)
	return count
}

func (c *Control) VipRipPortCounters(vip, rip IP4, port uint16, clear bool) counters {
	var raw [MAX_CPU]raw_counters
	type vip_rip_port struct {
		vip  IP4
		rip  IP4
		port uint16
		pad  uint16
	}
	vrp := vip_rip_port{vip: vip, rip: rip, port: port, pad: 0}

	if clear {
		xdp.BpfMapUpdateElem(c.vip_rip_port_counters, uP(&vrp), uP(&raw), xdp.BPF_ANY)
	}
	xdp.BpfMapLookupElem(c.vip_rip_port_counters, uP(&vrp), uP(&raw))

	var t raw_counters
	for _, r := range raw {
		t.add(r)
	}
	cooked := t.cook()
	cooked.Timestamp = time.Now()
	cooked.Ip = rip

	if m := c.ReadMAC(rip); m != nil {
		cooked.MAC = *m
	} else {
		cooked.MAC = MAC{}
	}

	return cooked
}

func (c *Control) VipRipPortConcurrent(vip, rip IP4, port uint16, era uint64) int32 {
	var curr [MAX_CPU]int32
	var zero [MAX_CPU]int32
	type vip_rip_port struct {
		vip  IP4
		rip  IP4
		port uint16
		pad  uint16
	}

	vrp := vip_rip_port{vip: vip, rip: rip, port: port, pad: uint16(era % 2)}

	xdp.BpfMapLookupElem(c.vip_rip_port_concurrent, uP(&vrp), uP(&curr))
	xdp.BpfMapUpdateElem(c.vip_rip_port_concurrent, uP(&vrp), uP(&zero), xdp.BPF_ANY)

	var total int32
	for _, t := range curr {
		total += t
	}
	return total
}

func (c *Control) FlowQueue() (*[FLOW_STATE]byte, bool) {
	var entry [FLOW_STATE]byte

	if xdp.BpfMapLookupAndDeleteElem(c.flow_queue, nil, uP(&entry)) != 0 {
		return nil, false
	}

	return &entry, true
}

func (c *Control) UpdateFlow(f []byte) {
	xdp.BpfMapUpdateElem(c.flows, uP(&f[0]), uP(&f[FLOW]), xdp.BPF_ANY)
}

func (c *Control) GlobalStats(clear bool) counters {
	var zero uint32 = 0
	var stats [MAX_CPU]raw_counters
	var t raw_counters

	if clear {
		xdp.BpfMapUpdateElem(c.stats, uP(&zero), uP(&stats), xdp.BPF_ANY)
	}

	xdp.BpfMapLookupElem(c.stats, uP(&zero), uP(&stats))

	for _, s := range stats {
		t.add(s)
	}
	return t.cook()
}

func (c *Control) VipRipPortConcurrents(vip, rip IP4, port uint16) chan int64 {

	counters := make(chan int64, 100)

	go func() {

		last, _ := c.Era()
		conn := c.VipRipPortConcurrent(vip, rip, port, 0) // ensure that both counter
		conn = c.VipRipPortConcurrent(vip, rip, port, 1)  // slots are created

		for {
			time.Sleep(1 * time.Second)

			next, _ := c.Era()
			if last != next {
				conn = c.VipRipPortConcurrent(vip, rip, port, last)
				last = next

				if conn < 0 {
					counters <- 0
				} else {
					counters <- int64(conn)
				}
			}
		}
	}()

	return counters
}

func (c *Control) VipRipPortConcurrents2(vip, rip IP4, port uint16, done chan bool) chan uint64 {

	counters := make(chan uint64, 10)

	go func() {

		last, _ := c.Era()
		conn := c.VipRipPortConcurrent(vip, rip, port, 0) // ensure that both counter
		conn = c.VipRipPortConcurrent(vip, rip, port, 1)  // slots are created

		ticker := time.NewTicker(1 * time.Second)

		defer func() {
			ticker.Stop()
		}()

		for {
			select {
			case <-ticker.C:

				next, _ := c.Era()
				if last != next {
					conn = c.VipRipPortConcurrent(vip, rip, port, last)
					//fmt.Println(">>>", last, conn)
					last = next
					if conn < 0 {
						conn = 0
					}

					select {
					case counters <- uint64(conn):
					default:
					}
				}
			case <-done:
				return
			}

		}
	}()

	return counters
}
