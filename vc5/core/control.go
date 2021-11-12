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
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"
	"unsafe"

	"bpf"
	//"vc5/rendezvous"
	"vc5/stats"
	"vc5/types"
	"vc5/xdp"
)

type scounters = types.Scounters
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
const MAX_CPU = 256
const INTERVAL = 5

type Control struct {
	xdp       *xdp.XDP_
	era       uint64
	interval  uint8
	scounters chan scounters
	counters  chan counters
	rhi       chan rhi

	interfaces              int
	service_backend         int
	rip_to_mac              int
	nat_to_vip_rip          int
	vip_rip_to_nat          int
	clocks                  int
	vip_rip_port_counters   int
	vip_rip_port_concurrent int
	stats                   int
	flow_queue              int
	flows                   int

	//// logger *logger

	ipaddr  IP4
	hwaddr  MAC
	ifindex uint32
}

func (c *Control) Era() (uint64, uint8) {
	return c.era, c.interval
}

func (c *Control) IPAddr() [4]byte {
	return c.ipaddr
}

func (c *Control) SCounters() chan scounters {
	return c.scounters
}
func (c *Control) Counters() chan counters {
	return c.counters
}
func (c *Control) RHI() chan rhi {
	return c.rhi
}

type rhi = types.RHI

type service struct {
	vip  IP4
	port [2]byte
	pad  [2]byte
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

func (c *Control) global_update() {
	var zero uint32 = 0
	c.era = 0

	type clocks struct {
		era  uint64
		time uint64
	}

	var clock clocks

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

func New(ipaddr IP4, veth string, vip IP4, hwaddr [6]byte, native, bridge bool, peth ...string) *Control {

	var c Control

	c.interval = INTERVAL
	c.ipaddr = ipaddr
	////c.logger = NewLogger()

	prog := "xdp_main"

	if bridge {
		prog = "xdp_main_bridge"
	}

	x, e := xdp.LoadBpfFile(veth, bpf.BPF_bpf, prog, native, peth...)

	if e != nil {
		log.Fatal(e)
	}

	c.xdp = x

	c.scounters = make(chan scounters, 1000)
	c.counters = make(chan counters, 1000)
	c.rhi = make(chan rhi, 1000)

	c.interfaces = c.find_map("interfaces", 4, 16)
	c.service_backend = c.find_map("service_backend", 8, 65536*12+12+1)
	c.rip_to_mac = c.find_map("rip_to_mac", 4, 6)
	c.nat_to_vip_rip = c.find_map("nat_to_vip_rip", 4, 24)
	c.vip_rip_to_nat = c.find_map("vip_rip_to_nat", 8, 4)
	c.clocks = c.find_map("clocks", 4, 16)
	c.vip_rip_port_counters = c.find_map("vip_rip_port_counters", 12, 8*6)
	c.vip_rip_port_concurrent = c.find_map("vip_rip_port_concurrent", 12, 4)
	c.stats = c.find_map("stats", 4, 8*6)
	c.flow_queue = c.find_map("flow_queue", 0, FLOW_STATE)
	c.flows = c.find_map("flows", FLOW, STATE)

	if p, err := net.InterfaceByName(peth[0]); err != nil {
		fmt.Println(peth, err)
		return nil
	} else {
		c.ifindex = uint32(p.Index)
		copy(c.hwaddr[:], p.HardwareAddr[:])
	}

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

	go c.global_update()
	go c.global_stats()
	go stats.Stats_server(c.rhi, c.scounters, c.counters)

	return &c
}

//nat->vip/rip
//vip/rip->nat

func (c *Control) SetNatVipRip(nat, vip, rip, src IP4, iface string, vlan uint16) {

	ifindex := c.ifindex
	ipaddr := c.ipaddr
	hwaddr := c.hwaddr

	if iface != "" {
		i, err := net.InterfaceByName(iface)

		if err != nil {
			panic(iface + " not found")
		}

		ifindex = uint32(i.Index)
		ipaddr = src
		copy(hwaddr[:], i.HardwareAddr[:])
	}

	vr := vip_rip_src_if{vip: vip, rip: rip, src: ipaddr, ifindex: ifindex, hwaddr: hwaddr, vlan_hi: byte(vlan >> 8), vlan_lo: byte(vlan & 0xff)}

	xdp.BpfMapUpdateElem(c.nat_to_vip_rip, uP(&nat), uP(&vr), xdp.BPF_ANY)
	xdp.BpfMapUpdateElem(c.vip_rip_to_nat, uP(&vr), uP(&nat), xdp.BPF_ANY)

}

func (c *Control) SetRip(rip IP4) {
	var mac MAC
	xdp.BpfMapUpdateElem(c.rip_to_mac, uP(&rip), uP(&mac), xdp.BPF_ANY)
	go ping(rip)
}

func (c *Control) SetBackends2(vip IP4, port uint16, backends [65536][12]byte, least [12]byte, weight byte) {
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

func ping(ip IP4) {
	command := fmt.Sprintf("ping -n -c 1 -w 1  %d.%d.%d.%d >/dev/null 2>&1", ip[0], ip[1], ip[2], ip[3])
	exec.Command("/bin/sh", "-c", command).Output()
}

func (c *Control) VipRipPortCounters(vip, rip IP4, port uint16) counters {
	var raw [MAX_CPU]raw_counters
	type vip_rip_port struct {
		vip  IP4
		rip  IP4
		port uint16
		pad  uint16
	}
	vrp := vip_rip_port{vip: vip, rip: rip, port: port, pad: 0}

	xdp.BpfMapUpdateElem(c.vip_rip_port_counters, uP(&vrp), uP(&raw), xdp.BPF_NOEXIST)
	xdp.BpfMapLookupElem(c.vip_rip_port_counters, uP(&vrp), uP(&raw))

	var t raw_counters
	for _, r := range raw {
		t.add(r)
	}
	return t.cook()
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

func (c *Control) xxVipRipPortConcurrent(vip, rip IP4, port uint16, p bool) int32 {
	var concurrent [MAX_CPU]int32
	type vip_rip_port struct {
		vip  IP4
		rip  IP4
		port uint16
		pad  uint16
	}
	pad := uint16(0)

	if p {
		pad = 1
	}

	var zero [MAX_CPU]int32

	vrp := vip_rip_port{vip: vip, rip: rip, port: port, pad: pad}

	xdp.BpfMapLookupElem(c.vip_rip_port_concurrent, uP(&vrp), uP(&concurrent))
	xdp.BpfMapUpdateElem(c.vip_rip_port_concurrent, uP(&vrp), uP(&zero), xdp.BPF_ANY)

	var total int32
	for _, t := range concurrent {
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

func (c *Control) _VRPStats(v, r IP4, port uint16, counters chan counters) {
	last, _ := c.Era()
	conn := c.VipRipPortConcurrent(v, r, port, 0) // ensure that both counter
	conn = c.VipRipPortConcurrent(v, r, port, 1)  // slots are created

	for {
		time.Sleep(1 * time.Second)

		counter := c.VipRipPortCounters(v, r, port)

		next, _ := c.Era()

		if last != next {
			conn = c.VipRipPortConcurrent(v, r, port, last)
			last = next
		}

		if conn < 0 {
			conn = 0
		}

		counter.Ip = r
		counter.Concurrent = int64(conn)
		counters <- counter
	}
}

func (c *Control) GlobalStats() counters {
	var zero uint32 = 0
	var stats [MAX_CPU]raw_counters
	var t raw_counters

	xdp.BpfMapLookupElem(c.stats, uP(&zero), uP(&stats))

	for _, s := range stats {
		t.add(s)
	}
	return t.cook()
}

func (c *Control) global_stats() {
	var prev counters
	var avg []uint64

	for n := 0; ; n++ {
		time.Sleep(1 * time.Second)

		count := c.GlobalStats()

		latency := count.Fp_time
		if count.Fp_count > 0 {
			latency /= count.Fp_count
		}

		avg = append(avg, latency)
		for len(avg) > 4 {
			avg = avg[1:]
		}

		latency = 0

		if len(avg) > 0 {
			for _, v := range avg {
				latency += v
			}
			latency /= uint64(len(avg))
		}

		count.Latency = latency
		count.Pps = (count.Rx_packets - prev.Rx_packets) // uint64(interval)
		c.Counters() <- count

		if n%10 == 0 {
			fmt.Printf(">>> %d pps, %d ns avg. latency\n", count.Pps, count.Latency)
		}
		prev = count
	}
}
