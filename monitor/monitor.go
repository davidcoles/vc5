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
	//	"fmt"
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
	IP  IP4
	MAC MAC
	VID uint16
	Idx uint16
}

type Metadata = healthchecks.Metadata
type Healthchecks = healthchecks.Healthchecks

type context struct {
	sock string
	nat  IP4
	vip  IP4
	l4   L4
	log  types.Logger
}

type Service struct {
	Metadata   Metadata
	Health     map[IP4]bool
	Healthy    bool
	Fallback   bool
	Sticky     bool
	Leastconns IP4
	Weight     uint8
}

type Virtual struct {
	Services map[L4]Service
	Metadata Metadata
	Healthy  bool
}

type Report struct {
	Virtuals map[IP4]Virtual
	Backends map[IP4]Backend
}

func Monitor(h *Healthchecks, ip IP4, sock string, lookup func(ip IP4) (MAC, bool), l types.Logger) *Mon {
	m := &Mon{}
	m.fn = m.monitor(h, ip, sock, lookup, l)
	return m
}

type Mon struct {
	fn func(*healthchecks.Healthchecks, bool) Report
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

func (m *Mon) monitor(h *Healthchecks, ip IP4, sock string, lookup func(ip IP4) (MAC, bool), l types.Logger) func(*Healthchecks, bool) Report {

	type be2 struct {
		IP  IP4
		VID uint16
	}

	virts := map[IP4]*Virt{}
	//backends := map[uint16]IP4{}
	backends2 := map[uint16]be2{}

	update := func(h *Healthchecks, fin bool) {

		if h != nil {

			//backends = h.Backend

			backends2 = map[uint16]be2{}
			//for k, v := range h.Backend {
			for k, v := range h.Backends() {
				_, _, vid := h.Iface(v)
				backends2[k] = be2{IP: v, VID: vid}
			}

			for vip, services := range h.Virtual {
				if v, ok := virts[vip]; ok {
					v.Reconfigure(services)
				} else {
					virts[vip] = StartVirt(services, context{vip: vip, nat: ip, sock: sock, log: l})
				}
			}

			for k, v := range virts {
				if _, ok := h.Virtual[k]; !ok {
					v.Close()
					delete(virts, k)
				}
			}
		}

		if fin {
			for k, v := range virts {
				v.Close()
				delete(virts, k)
			}
		}
	}

	update(h, false)

	return func(h *Healthchecks, fin bool) Report {
		update(h, false)

		var r Report

		r.Virtuals = map[IP4]Virtual{}
		for k, fn := range virts {
			v := fn.Status()
			r.Virtuals[k] = v
		}

		all := []IP4{}

		for _, v := range backends2 {
			all = append(all, v.IP)
		}

		r.Backends = map[IP4]Backend{}
		for k, v := range backends2 {
			var mac MAC
			if lookup != nil {
				mac, _ = lookup(v.IP)
			}

			backend := Backend{IP: v.IP, MAC: mac, VID: v.VID, Idx: k}
			r.Backends[v.IP] = backend
		}

		update(nil, fin)

		return r
	}
}

type Virt struct {
	f func(*healthchecks.Virtual, bool) Virtual
}

func StartVirt(services healthchecks.Virtual, c context) *Virt {
	v := &Virt{}
	v.f = virtual(&services, c)
	return v
}

func (v *Virt) Reconfigure(services healthchecks.Virtual) {
	v.f(&services, false)
}

func (v *Virt) Close() {
	v.f(nil, true)
}

func (v *Virt) Status() Virtual {
	return v.f(nil, false)
}

func virtual(services *healthchecks.Virtual, c context) func(*healthchecks.Virtual, bool) Virtual {

	svcs := map[L4]*Service_{}

	var m Metadata

	update := func(services *healthchecks.Virtual, fin bool) {
		if services != nil {
			m = services.Metadata

			for k, v := range services.Services {
				if svc, ok := svcs[k]; ok {
					svc.Reconfigure(v)
				} else {
					con := c
					con.vip = c.vip
					con.l4 = k
					svcs[k] = StartService(v, con)
				}
			}

			for k, v := range svcs {
				if _, ok := services.Services[k]; !ok {
					v.Close()
					delete(svcs, k)
				}
			}
		}

		if fin {
			for k, v := range svcs {
				v.Close()
				delete(svcs, k)
			}
		}
	}

	update(services, false)

	return func(services *healthchecks.Virtual, fin bool) Virtual {

		update(services, false)

		status := map[L4]Service{}
		for k, v := range svcs {
			status[k] = v.Status()
		}

		var healthy bool = true
		for _, s := range status {
			if !s.Healthy {
				healthy = false
			}
		}

		update(nil, fin)

		return Virtual{Services: status, Healthy: healthy, Metadata: m}
	}
}

type Service_ struct {
	f func(*healthchecks.Service, bool) Service
}

func StartService(s healthchecks.Service, c context) *Service_ {
	svc := &Service_{}
	svc.f = svc.init(&s, c)
	return svc
}

func (s *Service_) Status() Service {
	return s.f(nil, false)
}

func (s *Service_) Reconfigure(service healthchecks.Service) {
	s.f(&service, false)
}

func (s *Service_) Close() {
	s.f(nil, true)
}

func (s *Service_) init(service *healthchecks.Service, c context) func(*healthchecks.Service, bool) Service {

	reals := map[IP4]*Real{}
	var fallback *Real
	var metadata Metadata
	var minimum uint16
	var sticky bool

	update := func(service *healthchecks.Service, fin bool) {
		if service != nil {

			sticky = service.Sticky
			minimum = service.Minimum
			metadata = service.Metadata

			for real, r := range service.Reals {
				if _, ok := reals[real]; ok {
					reals[real].Reconfigure(r)
				} else {
					reals[real] = StartReal(r, c, false)
				}
			}

			if service.Fallback {
				r := healthchecks.Real{Checks: service.Local, RIP: c.vip}
				if fallback == nil {
					fallback = StartReal(r, c, true)
				} else {
					fallback.Reconfigure(r)
				}
			} else {
				if fallback != nil {
					fallback.Close()
					fallback = nil
				}
			}

			for real, fn := range reals {
				if _, ok := service.Reals[real]; !ok {
					fn.Close()
					delete(reals, real)
				}
			}
		}

		if fin {
			if fallback != nil {
				fallback.Close()
			}
			for k, fn := range reals {
				fn.Close()
				delete(reals, k)
			}
		}
	}

	update(service, false)

	return func(service *healthchecks.Service, fin bool) Service {
		update(service, false)

		status := Service{
			Health:   map[IP4]bool{},
			Metadata: metadata,
			Sticky:   sticky,
		}
		var healthy uint16

		for k, v := range reals {
			b := v.Status()

			if b {
				healthy++
			}

			status.Health[k] = b
		}

		if healthy >= minimum {
			status.Healthy = true
		} else if fallback != nil {
			if fallback.Status() {
				status.Healthy = true
				status.Fallback = true
			}
		}

		//status.Leastconns = 3
		//status.Weight = 128

		update(nil, fin)

		return status
	}
}

type Real struct {
	f func(*healthchecks.Real, bool) bool
	n uint16
}

func StartReal(real healthchecks.Real, c context, local bool) *Real {
	r := &Real{n: real.Index}
	r.f = rip(real, c, local)
	return r
}

func (r *Real) Close() {
	r.f(nil, true)
}

func (r *Real) Reconfigure(real healthchecks.Real) {
	r.f(&real, false)
}

func (r *Real) Status() bool {
	return r.f(nil, false)
}

func rip(real healthchecks.Real, c context, local bool) func(*healthchecks.Real, bool) bool {
	//fmt.Println("RIP:", real, c)
	var up bool

	nat := c.vip

	if !local {
		nat = natify(c.nat, real.NAT)
	}

	ch := checks(&up, nat, real.RIP, c.vip, c.l4.Port, c.sock, real.Checks, c.log)

	//fmt.Println(">>>>>>>>>", real.RIP)

	return func(ip *healthchecks.Real, fin bool) bool {

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

func checks(up *bool, nat IP4, rip, vip IP4, port uint16, sock string, checks Checks, l types.Logger) chan Checks {

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
					//fmt.Println(nat, rip, vip, port, "went", *up)
					l.NOTICE("monitor", nat, rip, vip, port, "went", *up)
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

	//fmt.Println("CHECKING", nat)

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
