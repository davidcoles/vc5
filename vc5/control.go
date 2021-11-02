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
	"fmt"
	"log"
	"net"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"example.com/bpf"
	"example.com/xdp"
)

const FLOW = 12
const STATE = 32
const FLOW_STATE = FLOW + STATE

type IP4 [4]byte
type IP6 [16]byte
type MAC [6]byte
type uP = unsafe.Pointer

const MAX_CPU = 256

func (i IP4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3])
}

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

type Control struct {
	xdp                     *xdp.XDP_
	scounters               chan scounters
	rhi                     chan rhi
	interfaces              int
	service_backend         int
	queue_map               int
	rip_to_mac              int
	nat_to_vip_rip          int
	vip_rip_to_nat          int
	clocks                  int
	vip_rip_port_counters   int
	vip_rip_port_concurrent int
	stats                   int
	flow_queue              int
	flows                   int
	timestamp               int64
	logger                  *logger

	latency uint64
	pps     uint64
	raw     raw_counters

	ipaddr  IP4
	hwaddr  MAC
	ifindex uint32
}

type rhi struct {
	ip IP4
	up bool
}

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

func (c *counters) AddRaw(r raw_counters) {
	c.New_flows += r.New_flows
	c.Rx_packets += r.Rx_packets
	c.Rx_bytes += r.Rx_bytes
	c.fp_count += r.fp_count
	c.fp_time += r.fp_time
	c.qfailed += r.qfailed
}

func (c *raw_counters) AddRaw(r raw_counters) {
	c.New_flows += r.New_flows
	c.Rx_packets += r.Rx_packets
	c.Rx_bytes += r.Rx_bytes
	c.fp_count += r.fp_count
	c.fp_time += r.fp_time
	c.qfailed += r.qfailed
}

type raw_counters struct {
	New_flows  uint64 `json:"total_connections"`
	Rx_packets uint64 `json:"rx_packets"`
	Rx_bytes   uint64 `json:"rx_bytes"`
	fp_count   uint64
	fp_time    uint64
	qfailed    uint64
}
type counters struct {
	Up         bool   `json:"up"`
	MAC        string `json:"mac"`
	Concurrent int64  `json:"current_connections"`
	New_flows  uint64 `json:"total_connections"`
	Rx_packets uint64 `json:"rx_packets"`
	Rx_bytes   uint64 `json:"rx_octets"`
	qfailed    uint64
	fp_count   uint64
	fp_time    uint64
	ip         IP4
}
type scounters struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Up          bool   `json:"up"`
	Nalive      uint   `json:"live_backends"`
	Need        uint   `json:"need_backends"`
	Concurrent  int64  `json:"current_connections"`
	New_flows   uint64 `json:"total_connections"`
	Rx_packets  uint64 `json:"rx_packets"`
	Rx_bytes    uint64 `json:"rx_octets"`
	fp_count    uint64
	fp_time     uint64

	name     string
	Backends map[string]counters `json:"backends"`
}

type interfaces struct {
	ifindex uint32
	ipaddr  IP4
	hwaddr  [6]byte
	padding [2]byte
}

func ulimit() {
	var rLimit syscall.Rlimit
	RLIMIT_MEMLOCK := 8
	if err := syscall.Getrlimit(RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatal("Error Getting Rlimit ", err)
	}
	rLimit.Max = 0xffffffffffffffff
	rLimit.Cur = 0xffffffffffffffff
	if err := syscall.Setrlimit(RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatal("Error Setting Rlimit ", err)
	}
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

func (c *Control) global_stats() {
	var zero uint32 = 0
	var tick int64
	var prev raw_counters
	var avg []uint64

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
		c.timestamp = tick //timestamp
		tick++
		clock.era = uint64(tick)
		xdp.BpfMapUpdateElem(c.clocks, uP(&zero), uP(&clock), xdp.BPF_ANY)

		var stats [MAX_CPU]raw_counters
		var t raw_counters

		xdp.BpfMapLookupElem(c.stats, uP(&zero), uP(&stats))

		for _, s := range stats {
			t.AddRaw(s)
		}

		latency := t.fp_time
		if t.fp_count > 0 {
			latency /= t.fp_count
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

		c.latency = latency
		c.pps = (t.Rx_packets - prev.Rx_packets) / 10 // see sleep below
		c.raw = t

		fmt.Printf(">>> %d pps, %d ns avg. latency\n", c.pps, latency)
		prev = t

		time.Sleep(10 * time.Second) // DONT CHANGE SLEEP - breaks concurrents
	}
}

func New(visible, veth string, hwaddr [6]byte, native, bridge bool, peth ...string) *Control {
	ulimit()

	ipaddr, ok := parseIP(visible)

	if !ok {
		log.Fatal(visible)
	}

	var c Control

	c.ipaddr = ipaddr
	c.logger = NewLogger()

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
	c.rhi = make(chan rhi, 1000)

	var t_ tuple
	c.interfaces = c.find_map("interfaces", 4, 16)
	//c.service_backend = c.find_map("service_backend", 8, 65536*10)
	c.service_backend = c.find_map("service_backend", 8, 65536*12)
	c.queue_map = c.find_map("queue_map", 0, int(unsafe.Sizeof(t_)))
	c.rip_to_mac = c.find_map("rip_to_mac", 4, 6)
	c.nat_to_vip_rip = c.find_map("nat_to_vip_rip", 4, 24)
	c.vip_rip_to_nat = c.find_map("vip_rip_to_nat", 8, 4)

	c.clocks = c.find_map("clocks", 4, 16)
	c.vip_rip_port_counters = c.find_map("vip_rip_port_counters", 12, 8*6)
	c.vip_rip_port_concurrent = c.find_map("vip_rip_port_concurrent", 12, 4)
	c.stats = c.find_map("stats", 4, 8*6)
	c.flow_queue = c.find_map("flow_queue", 0, FLOW_STATE)
	c.flows = c.find_map("flows", FLOW, STATE)

	var zero uint32 = 0
	var one uint32 = 1

	p, _ := net.InterfaceByName(peth[0])
	v, _ := net.InterfaceByName(veth)

	var phy interfaces
	phy.ifindex = uint32(p.Index)
	phy.ipaddr = ipaddr
	copy(phy.hwaddr[:], p.HardwareAddr[:])

	c.ifindex = phy.ifindex
	c.hwaddr = phy.hwaddr

	var vir interfaces
	vir.ifindex = uint32(v.Index)
	vir.ipaddr = IP4{10, 0, 0, 1}
	//peer := [6]byte{0, 1, 2, 3, 4, 5}
	//copy(vir.hwaddr[:], peer[:])
	vir.hwaddr = hwaddr

	//var tx_port int
	//tx_port = c.find_map("tx_port", 4, 4)
	//xdp.BpfMapUpdateElem(tx_port, uP(&zero), uP(&(vir.ifindex)), xdp.BPF_ANY)

	xdp.BpfMapUpdateElem(c.interfaces, uP(&zero), uP(&phy), xdp.BPF_ANY)
	xdp.BpfMapUpdateElem(c.interfaces, uP(&one), uP(&vir), xdp.BPF_ANY)

	go c.global_stats()
	go c.stats_server()

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

func (c *Control) SetBackends(vip IP4, port uint16, be [][12]byte) {

	var s service
	s.vip = vip
	s.port[0] = byte((port >> 8) & 0xff)
	s.port[1] = byte(port & 0xff)

	backends, stats := Rendezvous3(be)

	fmt.Println(stats)

	xdp.BpfMapUpdateElem(c.service_backend, uP(&s), uP(&backends), xdp.BPF_ANY)
}

func (c *Control) ReadQueue() *tuple {
	var t tuple
	//return nil
	if xdp.BpfMapLookupAndDeleteElem(c.queue_map, nil, unsafe.Pointer(&t)) != 0 {
		return nil
	}

	return &t
}

func (c *Control) ReadMAC(ip IP4) *MAC {
	var m MAC
	if xdp.BpfMapLookupElem(c.rip_to_mac, uP(&ip), uP(&m)) != 0 {
		return nil
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
	var counter counters
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

	for _, r := range raw {
		counter.AddRaw(r)
	}

	return counter
}

func (c *Control) VipRipPortConcurrent(vip, rip IP4, port uint16, p bool) int32 {
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

// c.flows = c.find_map("flows", 12, 24)
func (c *Control) UpdateFlow(f []byte) {
	//fmt.Println(f)
	xdp.BpfMapUpdateElem(c.flows, uP(&f[0]), uP(&f[FLOW]), xdp.BPF_ANY)
}
