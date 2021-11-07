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
	"sort"
	"time"
)

const ENABLE_HEALTHCHECKS = true

type vipstatus struct {
	port uint16
	up   bool
}

type update struct {
	rip IP4
	mac MAC
	up  bool
}

//func (c *Control) monitor_vip(service Service, vs chan vipstatus) {
func monitor_vip(c *Control, service Service, vs chan vipstatus) {
	vip := service.Vip
	port := service.Port
	backends := service.Rip

	name := fmt.Sprintf("%s:%d", vip, port)
	bup := make(map[IP4]bool)
	mac := make(map[IP4]MAC)
	ctr := make(map[IP4]counters)
	vlan := make(map[IP4]uint16)

	updates := make(chan update, 100)
	countersc := make(chan counters, 100)

	var live macripvids
	var nalive uint
	var up bool

	for _, r := range backends {
		var iface string
		if r.VLan != 0 {
			iface = fmt.Sprintf("vlan%d", r.VLan)
		}
		c.SetRip(r.Rip)
		c.SetNatVipRip(r.Nat, vip, r.Rip, r.Src, iface, r.VLan)
		vlan[r.Rip] = r.VLan
	}

	c.SetBackends(vip, port, live)

	fmt.Println("initial", vip, port, live, up)

	for _, r := range backends {
		var checks Checks
		checks.tcp = r.Tcp
		checks.http = r.Http
		checks.https = r.Https
		fmt.Println(r.Nat, r.Rip, checks)
		go monitor_nat(c, r.Nat, r.Rip, checks, updates)
		go c.vrp_stats(vip, r.Rip, port, countersc)
	}

	time.Sleep(1 * time.Second)

	for {
	do_select:
		select {
		case u := <-updates:
			bup[u.rip] = u.up
			mac[u.rip] = u.mac
			goto do_select
		case ct := <-countersc:
			ct.Up = bup[ct.ip]
			ct.MAC = mac[ct.ip].String()
			ctr[ct.ip] = ct
			s := scounters{name: name, Up: up, Nalive: nalive, Need: service.Need, Name: service.Name, Description: service.Description}
			s.Backends = make(map[string]counters)
			for k, v := range ctr {
				s.Backends[k.String()] = v
				s.Concurrent += v.Concurrent
				s.New_flows += v.New_flows
				s.Rx_packets += v.Rx_packets
				s.Rx_bytes += v.Rx_bytes
			}

			c.scounters <- s
			goto do_select
		default:
		}

		var new macripvids

		for r, m := range mac {
			v := vlan[r]
			h := uint8(v >> 8)
			l := uint8(v & 0xff)
			if bup[r] && cmpmac(m, [6]byte{0, 0, 0, 0, 0, 0}) != 0 {
				new = append(new, [12]byte{m[0], m[1], m[2], m[3], m[4], m[5], r[0], r[1], r[2], r[3], h, l})
			}
		}

		sort.Sort(new)

		was := up

		if !cmpmacripvids(live, new) {
			live = new

			if service.Need > 0 {
				up = uint(len(live)) >= service.Need
			} else {
				up = len(live) > 0
			}

			if up {
				c.SetBackends(vip, port, live)
			} else {
				c.SetBackends(vip, port, macripvids{})
			}

			// send update - mark vip up/down etc
			fmt.Println("changed", vip, port, live, up)
		}

		if was != up {
			c.Log(0, fmt.Sprint("VIP state change: ", vip, " -> ", ud(up)))
		}

		vs <- vipstatus{port: port, up: up}

		nalive = uint(len(live))

		time.Sleep(1 * time.Second)
	}

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

			for _, c := range checks.http {
				if !HTTPCheck(nat, c.Port, c.Path, int(c.Expect)) {
					ok = false
				}
			}

			for _, c := range checks.https {
				if !HTTPSCheck(nat, c.Port, c.Path, int(c.Expect)) {
					ok = false
				}
			}

			for _, c := range checks.tcp {
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

		if cmpmac(m2, mac) != 0 {
			changed = true
			mac = m2
			c.Log(0, fmt.Sprint("RIP MAC change: ", rip, " -> ", mac))
		}

		if ok != alive {

			fmt.Println(rip, "changed", alive, mac)

			changed = true
			alive = ok

			c.Log(0, fmt.Sprint("RIP state change: ", rip, " -> ", ud(alive)))
		}

		if changed {
			updates <- update{rip: rip, mac: mac, up: alive}
		}

		time.Sleep(9 * time.Second)
	}
}
