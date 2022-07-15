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

package monitor

import (
	"fmt"
	"time"

	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/netns"
	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type MAC = types.MAC
type L4 = types.L4

type Checks = types.Checks
type Check = types.Check

type Backend struct {
	MAC MAC
	IP  IP4
}

type Metadata = healthchecks.Metadata
type Reals map[uint16]Real
type Real = healthchecks.Real
type Service_ = healthchecks.Service_
type Virtual_ = healthchecks.Virtual_
type Healthchecks = healthchecks.Healthchecks

type context struct {
	sock string
	nat  IP4
	vip  IP4
	l4   L4
}

type Status struct {
	Metadata Metadata
	Health   map[uint16]bool `json:"health"`
	Healthy  bool            `json:"healthy"`
}

type Virtual struct {
	Services map[L4]Status
	Metadata Metadata
	Healthy  bool
}

type Report struct {
	Virtuals map[IP4]Virtual
	Backends map[uint16]Backend
}

type Mon struct {
	fn func(*healthchecks.Healthchecks, bool) Report
}

func Monitor(h *Healthchecks, ip IP4, sock string, lookup func(ip IP4) (MAC, bool)) *Mon {
	fn := Monitor_(h, ip, sock, lookup)
	return &Mon{fn: fn}
}

func (m *Mon) Update(h *Healthchecks) Report {
	return m.fn(h, false)
}
func (m *Mon) Report() Report {
	return m.fn(nil, false)
}

func (m *Mon) Close() {
	m.fn(nil, true)
}

func natify(t [4]byte, p uint16) [4]byte { return [4]byte{t[0], t[1], byte(p >> 8), byte(p & 0xff)} }

func Monitor_(h *Healthchecks, ip IP4, sock string, lookup func(ip IP4) (MAC, bool)) func(*Healthchecks, bool) Report {

	x := map[IP4]func(*Virtual_, bool) Virtual{}
	backends := map[uint16]IP4{}

	update := func(h *Healthchecks, fin bool) {

		if h != nil {

			backends = h.Backends

			for vip, services := range h.Virtuals {
				if fn, ok := x[vip]; ok {
					fn(&services, false) // update sub-tree
				} else {
					x[vip] = virtual(&services, context{vip: vip, nat: ip, sock: sock})
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

	update(h, false)

	return func(h *Healthchecks, fin bool) Report {
		update(h, false)

		var r Report

		r.Virtuals = map[IP4]Virtual{}
		for k, fn := range x {
			v := fn(nil, false)
			r.Virtuals[k] = v
		}

		all := []IP4{}

		for _, v := range backends {
			all = append(all, v)
		}

		r.Backends = map[uint16]Backend{}
		for k, v := range backends {
			var mac MAC
			if lookup != nil {
				mac, _ = lookup(v)
			}
			r.Backends[k] = Backend{IP: v, MAC: mac}
		}

		update(nil, fin)

		return r
	}
}

func virtual(services *Virtual_, c context) func(*Virtual_, bool) Virtual {

	x := map[L4]func(*Service_, bool) Status{}

	var m Metadata

	update := func(services *Virtual_, fin bool) {
		if services != nil {
			m = services.Metadata

			for s, v := range services.Services {
				if _, ok := x[s]; ok {
					x[s](&v, false)
				} else {
					con := c
					con.vip = c.vip
					con.l4 = s
					x[s] = service(&v, con)
				}
			}

			for s, fn := range x {
				if _, ok := services.Services[s]; !ok {
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

	return func(services *Virtual_, fin bool) Virtual {

		update(services, false)

		y := map[L4]Status{}
		for k, fn := range x {
			y[k] = fn(nil, false)
		}

		var healthy bool = true
		for _, s := range y {
			if !s.Healthy {
				healthy = false
			}
		}

		update(nil, fin)

		return Virtual{Services: y, Healthy: healthy, Metadata: m}
	}
}

func service(service *Service_, c context) func(*Service_, bool) Status {

	x := map[uint16]func(*Real, bool) bool{}
	var m Metadata

	update := func(service *Service_, fin bool) {
		if service != nil {

			m = service.Metadata

			for real, r := range service.Reals {
				if _, ok := x[real]; ok {
					x[real](&r, false)
				} else {
					x[real] = rip(r, c)
				}
			}

			for real, fn := range x {
				if _, ok := service.Reals[real]; !ok {
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

	return func(service *Service_, fin bool) Status {
		update(service, false)

		status := Status{Health: map[uint16]bool{}, Metadata: m}
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

func rip(real Real, c context) func(*Real, bool) bool {
	//fmt.Println("RIP:", real, c)
	var up bool
	ch := checks(&up, natify(c.nat, real.NAT), real.RIP, c.vip, c.l4.Port, c.sock, real.Checks)

	return func(ip *Real, fin bool) bool {

		if ip != nil {
			ch <- ip.Checks
		}

		if fin {
			close(ch)
		}

		return up
	}
}

func rotate(b [5]bool, n bool) [5]bool {
	b[0] = b[1]
	b[1] = b[2]
	b[2] = b[3]
	b[3] = b[4]
	b[4] = n
	return b
}

func healthy(b [5]bool) bool {
	var ok bool = true
	for _, v := range b {
		if !ok && !v {
			return false // 2 strikes and you're out
		}
		if !v {
			ok = false
		}
	}
	return true
}

func checks(up *bool, nat IP4, rip, vip IP4, port uint16, sock string, checks Checks) chan Checks {

	ch := make(chan Checks)

	go func() {

		var last, ok bool
		history := [5]bool{false, false, true, true, true}

		for {
			select {
			case <-time.After(2 * time.Second):

				history = rotate(history, probes(nat, sock, checks))

				*up = healthy(history)

				if *up != last {
					fmt.Println(nat, rip, vip, port, "went", *up)
				}

				last = *up

			case checks, ok = <-ch:
				if !ok {
					return
				}
			}
		}
	}()

	return ch
}

func probes(nat IP4, path string, checks Checks) bool {

	for _, c := range checks.Http {
		if !netns.Probe(path, nat, "http", c) {
			return false
		}
	}

	for _, c := range checks.Https {
		if !netns.Probe(path, nat, "https", c) {
			return false
		}
	}

	for _, c := range checks.Tcp {
		if !netns.Probe(path, nat, "tcp", c) {
			return false
		}
	}

	for _, c := range checks.Syn {
		if !netns.Probe(path, nat, "syn", c) {
			return false
		}
	}

	for _, c := range checks.Dns {
		if !netns.Probe(path, nat, "dns", c) {
			return false
		}
	}

	return true
}
