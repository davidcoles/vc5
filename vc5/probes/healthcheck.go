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
	"vc5/logger"
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

type hwaddr struct {
	idx  uint16
	mac  MAC
	vlan uint16
	rip  IP4
}

func (p *Probes) ManageVIP(service Service, vs chan vipstatus, sc chan scounters) {
	go p.ManageVip(service, vs, sc)
}

func (p *Probes) ManageVip(service Service, vs chan vipstatus, sc chan scounters) {
	c := p.control
	logs := p.logger
	vip := service.Vip
	port := service.Port
	backends := service.Rip
	var live B12s
	var nalive uint
	var up bool

	hashed, stats := rendezvous.Rendezvous(live)

	c.SetBackends(vip, port, hashed, [12]byte{}, 0)
	//fmt.Println("initial", vip, port, live, up)

	name := fmt.Sprintf("%s:%d", vip, port)
	ctr := make(map[IP4]counters)

	countersc := make(chan counters, 100)

	for _, r := range backends {
		var iface string
		if r.VLan != 0 {
			iface = fmt.Sprintf("vlan%d", r.VLan)
		}
		c.SetRip(r.Rip)
		c.SetNatVipRip(r.Nat, vip, r.Rip, r.Src, iface, r.VLan)

		var checks Checks
		checks.Tcp = r.Tcp
		checks.Http = r.Http
		checks.Https = r.Https
		//fmt.Println(r.Nat, r.Rip, checks)
		logs.INFO(fmt.Sprint(r.Nat, r.Rip, checks))
		go p.manageBackend(vip, port, r, countersc, checks)
	}

	time.Sleep(1 * time.Second)

	for {
	do_select:
		select {
		case ct := <-countersc:
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

			sc <- s
			goto do_select
		default:
		}

		new := build_list(ctr)
		var least B12
		var weight uint8

		if service.LeastConns {
			new, least, weight = least_conns(ctr)
		}

		was := up

		if setsDiffer(live, new) {
			live = new
			hashed, stats = rendezvous.Rendezvous(live)
			nalive = uint(len(live))
			//fmt.Println(vip, port, stats, live, nalive)
			logs.INFO(fmt.Sprint(vip, port, stats, live, nalive))

			ips := make(map[[4]byte]uint8)
			for _, b := range live {
				m := MAC{b[0], b[1], b[2], b[3], b[4], b[5]}
				r := IP4{b[6], b[7], b[8], b[9]}
				if i, ok := p.backend[r]; ok {
					//fmt.Println(r, m, i)
					c.SetBackendRec(r, m, 0, i)
					ips[r] = i
				}
			}
			x, s := rendezvous.RipIndex(ips)
			fmt.Println(vip, port, s, x[0:32])
			c.SetBackendIdx(vip, port, x)
		}

		if service.Need > 0 {
			up = nalive >= service.Need
		} else {
			up = nalive > 0
		}

		c.SetBackends(vip, port, hashed, least, weight)

		if was != up {
			logs.NOTICE(fmt.Sprint("Service state change: ", vip, port, " -> ", ud(up)))
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
func (p *Probes) healthcheckBackend(vip IP4, port uint16, nat, rip IP4, checks Checks) chan bool {
	updates := make(chan update, 100)
	up := make(chan bool, 100)
	go p.healthcheckBackend_(vip, port, nat, rip, checks, updates)
	go func() {
		for u := range updates {
			up <- u.up
		}
	}()
	return up
}
func (p *Probes) healthcheckBackend_(vip IP4, port uint16, nat, rip IP4, checks Checks, updates chan update) {
	c := p.control
	var mac MAC

	alive := false

	for {
		ok := true

		go ping(rip)

		time.Sleep(1 * time.Second)

		for _, c := range checks.Http {
			//fmt.Println(nat, c.Port, c.Path, int(c.Expect), c.Host)
			if !HTTPCheck(nat, c.Port, c.Path, int(c.Expect), c.Host) {
				ok = false
			}
		}

		for _, c := range checks.Https {
			//fmt.Println(nat, c.Port, c.Path, int(c.Expect), c.Host)
			if !HTTPSCheck(nat, c.Port, c.Path, int(c.Expect), c.Host) {
				ok = false
			}
		}

		for _, c := range checks.Tcp {
			if !TCPCheck(nat, c.Port) {
				ok = false
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

			//fmt.Println(rip, "changed", alive, mac)

			changed = true
			alive = ok

			//c.Log(0, fmt.Sprint("RIP state change: ", rip, " -> ", ud(alive)))
			p.logger.NOTICE(fmt.Sprintf("Real server state change: %s:%d %s -> %s", vip, port, rip, ud(alive)))
		}

		if changed {
			updates <- update{rip: rip, mac: mac, up: alive}
		}

		time.Sleep(9 * time.Second)
	}
}

func (p *Probes) manageBackend(vip IP4, port uint16, real config.Real, counters chan counters, checks Checks) {
	c := p.control

	var up bool
	var ac int64

	rip := real.Rip

	status := p.healthcheckBackend(vip, port, real.Nat, rip, checks) // is backend up or down
	active := c.VipRipPortConcurrents(vip, rip, port)                // number of active connections
	prev := c.VipRipPortCounters(vip, rip, port, true)

	for {
		time.Sleep(1 * time.Second)

		counter := c.VipRipPortCounters(vip, rip, port, false)
		seconds := float64(counter.Timestamp.Sub(prev.Timestamp)) / float64(time.Second)
		counter.Rx_pps = uint64(float64(counter.Rx_packets-prev.Rx_packets) / seconds)
		counter.Rx_bps = uint64(float64(counter.Rx_bytes-prev.Rx_bytes) / seconds)

	poll_status:
		select {
		case up = <-status:
			goto poll_status
		case ac = <-active:
			goto poll_status
		default:
		}

		counter.Up = up
		counter.Concurrent = ac
		counters <- counter
		prev = counter
	}
}

func ping(ip IP4) {
	command := fmt.Sprintf("ping -n -c 1 -w 1  %d.%d.%d.%d >/dev/null 2>&1", ip[0], ip[1], ip[2], ip[3])
	exec.Command("/bin/sh", "-c", command).Output()
}

type Probes struct {
	control *Control
	logger  *logger.Logger
	backend map[IP4]uint8
}

func Manage(c *Control, l *logger.Logger, b map[IP4]uint8) *Probes {
	p := Probes{control: c, logger: l, backend: b}
	return &p
}

func (p *Probes) GlobalStats(cchan chan types.Counters) {
	go GlobalStats_(p.control, cchan, p.logger)
}

func GlobalStats_(c *Control, cchan chan types.Counters, l *logger.Logger) {
	var prev counters
	var avg []uint64

	c.GlobalStats(true)

	for n := 0; ; n++ {
		time.Sleep(1 * time.Second)

		count := c.GlobalStats(false)

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
		//c.Counters() <- count
		cchan <- count

		if n%10 == 0 {
			fmt.Printf("%d pps, %d ns avg. latency\n", count.Pps, count.Latency)
			//s := fmt.Sprintf(">>> %d pps, %d ns avg. latency", count.Pps, count.Latency)
			//l.INFO(s)
		}
		prev = count
	}
}
