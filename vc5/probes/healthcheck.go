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

package probes

import (
	"fmt"
	"math"
	"os/exec"
	"sort"
	"time"

	"vc5/config"
	"vc5/core"
	"vc5/rendezvous"
	"vc5/types"
)

type Control = core.Control
type IP4 = types.IP4
type IP6 = types.IP6
type MAC = types.MAC
type B12s = types.B12s
type B12 = types.B12

type Service = config.Service
type Checks = config.Checks

type scounters = types.Scounters
type counters = types.Counters

const ENABLE_HEALTHCHECKS = true

type vipstatus = Vipstatus
type Vipstatus struct {
	Port uint16
	Up   bool
}

type update struct {
	rip IP4
	mac MAC
	up  bool
}

//func (c *Control) monitor_vip(service Service, vs chan vipstatus) {
func MonitorVip(c *Control, service Service, vs chan vipstatus) {
	vip := service.Vip
	port := service.Port
	backends := service.Rip
	var live B12s
	var nalive uint
	var up bool

	hashed, stats := rendezvous.Rendezvous(live)

	c.SetBackends2(vip, port, hashed, [12]byte{}, 0)
	fmt.Println("initial", vip, port, live, up)

	name := fmt.Sprintf("%s:%d", vip, port)
	//bup := make(map[IP4]bool)
	//mac := make(map[IP4]MAC)
	ctr := make(map[IP4]counters)
	vlan := make(map[IP4]uint16)

	//updates := make(chan update, 100)
	countersc := make(chan counters, 100)

	for _, r := range backends {
		var iface string
		if r.VLan != 0 {
			iface = fmt.Sprintf("vlan%d", r.VLan)
		}
		c.SetRip(r.Rip)
		c.SetNatVipRip(r.Nat, vip, r.Rip, r.Src, iface, r.VLan)
		vlan[r.Rip] = r.VLan

		var checks Checks
		checks.Tcp = r.Tcp
		checks.Http = r.Http
		checks.Https = r.Https
		fmt.Println(r.Nat, r.Rip, checks)
		//go monitor_nat(c, r.Nat, r.Rip, checks, updates)
		go VRPStats(c, vip, r.Rip, port, r.VLan, countersc, r.Nat, checks)
	}

	time.Sleep(1 * time.Second)

	for {
	do_select:
		select {
		//case u := <-updates:
		//	bup[u.rip] = u.up
		//	mac[u.rip] = u.mac
		//	goto do_select
		case ct := <-countersc:
			//ct.Up = bup[ct.Ip]
			//ct.MAC = mac[ct.Ip]
			//bup[ct.Ip] = ct.Up
			//mac[ct.Ip] = ct.MAC
			ctr[ct.Ip] = ct
			s := scounters{Sname: name, Up: up, Nalive: nalive, Need: service.Need, Name: service.Name, Description: service.Description}
			s.Backends = make(map[string]counters)
			for k, v := range ctr {
				s.Backends[k.String()] = v
				s.Concurrent += v.Concurrent
				s.New_flows += v.New_flows
				s.Rx_packets += v.Rx_packets
				s.Rx_bytes += v.Rx_bytes
			}

			c.SCounters() <- s
			goto do_select
		default:
		}

		//var new B12s

		//for r, m := range mac {
		//	if bup[r] && types.Cmpmac(m, [6]byte{0, 0, 0, 0, 0, 0}) != 0 {
		//		new = append(new, makeB12(m, r, vlan[r]))
		//	}
		//}

		/*
			for r, c := range ctr {
				if c.Up && types.Cmpmac(c.MAC, MAC{}) != 0 {
					new = append(new, makeB12(c.MAC, r, vlan[r]))
				}
			}
		*/

		new := build_list(ctr)
		var least B12
		var weight uint8

		if service.LeastConns {
			new, least, weight = least_conns(ctr)
		}

		//sort.Sort(new)

		was := up

		//if !types.CmpB12s(live, new) {
		if setsDiffer(live, new) {
			live = new
			hashed, stats = rendezvous.Rendezvous(live)
			nalive = uint(len(live))
			fmt.Println(vip, port, stats, live, nalive)
		}

		if service.Need > 0 {
			up = nalive >= service.Need
		} else {
			up = nalive > 0
		}

		//if foo > 0 {
		//	fmt.Println("XXXX", out, foo)
		//}

		//var out B12
		//var foo uint8
		//ots := IP4{10, 7, 115, 126}
		//if bup[ots] {
		//	out = makeB12(mac[ots], ots, 0)
		//	foo = 128
		//}

		c.SetBackends2(vip, port, hashed, least, weight)
		//fmt.Println("changed", vip, port, live, up)
		//}

		if was != up {
			//c.Log(0, fmt.Sprint("VIP state change: ", vip, " -> ", ud(up)))
			vs <- vipstatus{Port: port, Up: up}
		}

		time.Sleep(3 * time.Second)
	}

}

func build_list(ctr map[IP4]counters) B12s {
	var new B12s
	for r, c := range ctr {
		if c.Up && types.Cmpmac(c.MAC, MAC{}) != 0 {
			new = append(new, makeB12(c.MAC, r, c.Vlan))
		}
	}
	return new
}

func avg_pps(c map[IP4]counters) uint64 {
	var pps, bps uint64
	for _, v := range c {
		pps += v.Rx_pps
		bps += v.Rx_bps
	}
	if len(c) > 0 {
		pps /= uint64(len(c))
		bps /= uint64(len(c))
	}
	return pps
}

func least_conns(c map[IP4]counters) (B12s, B12, uint8) {
	ctr := make(map[IP4]counters)

	// filter backends that are not up
	for k, v := range c {
		if v.Up {
			ctr[k] = v
		}
	}

	if len(ctr) < 2 {
		return build_list(ctr), B12{}, 0
	}

	var min counters
	var max counters
	var ok bool
	for _, v := range ctr {
		if min.Rx_pps == 0 && v.Rx_pps != 0 {
			min = v
			ok = true
		}
		if max.Rx_pps == 0 {
			max = v
		}
		if v.Rx_pps < min.Rx_pps {
			min = v
		}
		if v.Rx_pps > max.Rx_pps {
			max = v
		}
	}

	ctr2 := make(map[IP4]counters)
	for k, v := range ctr {
		if k != max.Ip {
			ctr2[k] = v
		}
	}

	ctr3 := make(map[IP4]counters)
	for k, v := range ctr {
		if k != min.Ip {
			ctr3[k] = v
		}
	}

	pps := avg_pps(ctr)
	pps2 := avg_pps(ctr2)
	pps3 := avg_pps(ctr3)

	if pps < 50000 {
		return build_list(ctr), B12{}, 0
	}

	if max.Rx_pps > ((pps2 * 5) / 4) {
		delete(ctr, max.Ip)
	}

	if ok && min.Rx_pps < ((pps3*9)/10) {

		//weight := uint8(255 * (float64((pps3 - min.Rx_pps)) / float64(pps3)))

		weight := uint8(math.Log(255*(float64((pps3-min.Rx_pps))/float64(pps3))) * 42)

		fmt.Println(min.Ip, min.Rx_pps, pps, weight)
		return build_list(ctr), makeB12(min.MAC, min.Ip, 0), weight
	}

	return build_list(ctr), B12{}, 0
}

func makeB12(m MAC, i IP4, v uint16) B12 {
	h := uint8(v >> 8)
	l := uint8(v & 0xff)
	return [12]byte{m[0], m[1], m[2], m[3], m[4], m[5], i[0], i[1], i[2], i[3], h, l}
}

func setsDiffer(a, b B12s) bool {
	sort.Sort(a)
	sort.Sort(b)
	return !types.CmpB12s(a, b)
}

func ud(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

func monitor_nat(c *Control, nat, rip IP4, checks Checks, updates chan update) {
	var mac MAC

	alive := false

	for {
		ok := true

		go ping(rip)

		time.Sleep(1 * time.Second)

		if ENABLE_HEALTHCHECKS {

			for _, c := range checks.Http {
				if !HTTPCheck(nat, c.Port, c.Path, int(c.Expect)) {
					ok = false
				}
			}

			for _, c := range checks.Https {
				if !HTTPSCheck(nat, c.Port, c.Path, int(c.Expect)) {
					ok = false
				}
			}

			for _, c := range checks.Tcp {
				if !TCPCheck(nat, c.Port) {
					ok = false
				}
			}
		}

		changed := false

		m := c.ReadMAC(rip)

		var m2 MAC

		if m != nil {
			m2 = *m
		}

		if types.Cmpmac(m2, mac) != 0 {
			changed = true
			mac = m2
			//c.Log(0, fmt.Sprint("RIP MAC change: ", rip, " -> ", mac))
		}

		if ok != alive {

			fmt.Println(rip, "changed", alive, mac)

			changed = true
			alive = ok

			//c.Log(0, fmt.Sprint("RIP state change: ", rip, " -> ", ud(alive)))
		}

		if changed {
			updates <- update{rip: rip, mac: mac, up: alive}
		}

		time.Sleep(9 * time.Second)
	}
}

//func monitor_nat(c *Control, nat, rip IP4, checks Checks, updates chan update) {
func VRPStats(c *Control, vip, rip IP4, port uint16, vlan uint16, counters chan counters, nat IP4, checks Checks) {

	var up bool
	var mac MAC

	updates := make(chan update, 100)

	//updates <- update{rip: rip, mac: mac, up: alive}

	go monitor_nat(c, nat, rip, checks, updates)

	last, _ := c.Era()
	conn := c.VipRipPortConcurrent(vip, rip, port, 0) // ensure that both counter
	conn = c.VipRipPortConcurrent(vip, rip, port, 1)  // slots are created

	prev := c.VipRipPortCounters(vip, rip, port, true)
	prev.Timestamp = time.Now()

	for {
		time.Sleep(1 * time.Second)

		counter := c.VipRipPortCounters(vip, rip, port, false)
		counter.Timestamp = time.Now()

		scnds := float64(counter.Timestamp.Sub(prev.Timestamp)) / float64(time.Second)

		counter.Rx_pps = uint64(float64(counter.Rx_packets-prev.Rx_packets) / scnds)
		counter.Rx_bps = uint64(float64(counter.Rx_bytes-prev.Rx_bytes) / scnds)

		next, _ := c.Era()
		if last != next {
			conn = c.VipRipPortConcurrent(vip, rip, port, last)
			last = next
		}

		if conn < 0 {
			conn = 0
		}

	do_select:
		select {
		case u := <-updates:
			up = u.up
			mac = u.mac
			goto do_select
		default:
		}

		counter.Up = up
		counter.MAC = mac

		counter.Ip = rip
		counter.Vlan = vlan
		counter.Concurrent = int64(conn)
		counters <- counter
		prev = counter
	}
}

func ping(ip IP4) {
	command := fmt.Sprintf("ping -n -c 1 -w 1  %d.%d.%d.%d >/dev/null 2>&1", ip[0], ip[1], ip[2], ip[3])
	exec.Command("/bin/sh", "-c", command).Output()
}
