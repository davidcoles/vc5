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

func (c *Control) vrp_stats(v, r IP4, port uint16, counters chan counters) {
	last := c.timestamp
	conn := c.VipRipPortConcurrent(v, r, port, true) // ensure that both counter
	conn = c.VipRipPortConcurrent(v, r, port, false) // slots are created

	for {
		time.Sleep(1 * time.Second)

		counter := c.VipRipPortCounters(v, r, port)

		next := c.timestamp

		if last != next {
			conn = c.VipRipPortConcurrent(v, r, port, last%2 == 0)
			last = next
		}

		if conn < 0 {
			conn = 0
		}

		counter.ip = r
		counter.Concurrent = int64(conn)
		counters <- counter
	}
}

func (c *Control) monitor_vip(service Service, vs chan vipstatus) {
	vip := service.Vip
	port := service.Port
	backends := service.Rip

	name := fmt.Sprintf("%s:%d", vip, port)
	bup := make(map[IP4]bool)
	mac := make(map[IP4]MAC)
	ctr := make(map[IP4]counters)

	updates := make(chan update, 100)
	countersc := make(chan counters, 100)

	var live macrips
	var nalive uint
	var up bool

	for _, r := range backends {
		c.SetRip(r.Rip)
		c.SetNatVipRip(r.Nat, vip, r.Rip)
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

		var new macrips

		for r, m := range mac {
			if bup[r] && cmpmac(m, [6]byte{0, 0, 0, 0, 0, 0}) != 0 {
				new = append(new, [10]byte{m[0], m[1], m[2], m[3], m[4], m[5], r[0], r[1], r[2], r[3]})
			}
		}

		sort.Sort(new)

		was := up

		if !cmpmacrips(live, new) {
			live = new

			if service.Need > 0 {
				up = uint(len(live)) >= service.Need
			} else {
				up = len(live) > 0
			}

			if up {
				c.SetBackends(vip, port, live)
			} else {
				c.SetBackends(vip, port, macrips{})
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
