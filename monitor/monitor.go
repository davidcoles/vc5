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
	"sync"
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

type Metadata = healthchecks.Metadata
type Healthchecks = healthchecks.Healthchecks
type Service = healthchecks.Service
type Probe = healthchecks.Probe
type Virtual = healthchecks.Virtual
type Backend = healthchecks.Backend
type Report = healthchecks.Healthchecks

type context struct {
	sock    string  // UNIX domain docket to communicate with netns NAT server
	base    [2]byte // 1st two octets of NAT /16 range
	vip     IP4
	l4      L4
	log     types.Logger
	new_vip bool
	new_svc bool
	new_rip bool
	notify  chan bool
}

func (m *Mon) manage(l types.Logger) {
	var changed bool
	var count uint64

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {

		case h, ok := <-m.in: // new config
			if !ok {
				return
			}
			//l.CRIT("CONFIG")
			m.fn(h, false) // apply the config
			changed = true // let downstream know of the change next tick

		case <-m.nt: // backend changed
			//l.CRIT("NOTIFICATION")
			changed = true

		case <-ticker.C: // once per second if changed and force every 60s to update ARP
			count++
			if changed || count%60 == 0 {
				select {
				case m.C <- m.fn(nil, false):
					//l.CRIT("SENT", count%60)
					changed = false
					count = 0
				default:
				}
			}
		}
	}
}

type Mon struct {
	fn func(*healthchecks.Healthchecks, bool) Report
	C  chan healthchecks.Healthchecks
	in chan *Healthchecks
	nt chan bool
}

func Monitor(h *Healthchecks, ip IP4, sock string, lookup func(ip IP4) (MAC, bool), l types.Logger) (*Mon, Healthchecks) {
	m := &Mon{C: make(chan Healthchecks), in: make(chan *Healthchecks), nt: make(chan bool)}
	m.fn = m.monitor(h, ip, sock, lookup, l)
	r := m.fn(nil, false)
	go m.manage(l)
	return m, r
}

func (m *Mon) Update(h *Healthchecks) {
	m.in <- h
}

func (m *Mon) Close() {
	m.fn(nil, true)
}

func natify(t [2]byte, p uint16) [4]byte { return [4]byte{t[0], t[1], byte(p >> 8), byte(p & 0xff)} }

func (m *Mon) monitor(h *Healthchecks, ip IP4, sock string, lookup func(ip IP4) (MAC, bool), l types.Logger) func(*Healthchecks, bool) Report {

	var status Healthchecks

	virts := map[IP4]*Virt{}
	backends := map[uint16]Backend{}

	update := func(h *Healthchecks, fin bool) {

		if h != nil {

			status = *h

			backends = map[uint16]Backend{}

			for k, v := range h.BackendIdx() {
				_, _, vid := h.Iface(v)
				backends[k] = Backend{IP: v, VID: vid}
			}

			for vip, services := range h.Virtual {
				if v, ok := virts[vip]; ok {
					v.Reconfigure(services)
				} else {
					virts[vip] = StartVirt(services, context{vip: vip, base: [2]byte{ip[0], ip[1]}, sock: sock, log: l, notify: m.nt})
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

		r := status                    // take a new copy of the config root
		r.Backends = map[IP4]Backend{} // clear deep structure
		r.Virtual = map[IP4]Virtual{}

		for k, fn := range virts {
			v := fn.Status()
			r.Virtual[k] = v
		}

		all := []IP4{}

		for _, v := range backends {
			all = append(all, v.IP)
		}

		for k, v := range backends {
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

	var virt Virtual
	svcs := map[L4]*Serv{}

	c.new_vip = true
	c.new_svc = true
	c.new_rip = true

	update := func(services *healthchecks.Virtual, fin bool) {
		if services != nil {

			virt = *services
			virt.Services = map[L4]Service{}

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

	c.new_vip = false

	return func(services *healthchecks.Virtual, fin bool) Virtual {

		update(services, false)

		virt.Healthy = true
		virt.Services = map[L4]Service{}
		for k, v := range svcs {
			s := v.Status()
			virt.Services[k] = s
			if !s.Healthy {
				virt.Healthy = false
			}
		}

		update(nil, fin)

		return virt
	}
}

type Serv struct {
	f func(*Service, bool) Service
}

func StartService(s Service, c context) *Serv {
	svc := &Serv{}
	svc.f = svc.init(&s, c)
	return svc
}

func (s *Serv) Status() Service {
	return s.f(nil, false)
}

func (s *Serv) Reconfigure(service Service) {
	s.f(&service, false)
}

func (s *Serv) Close() {
	s.f(nil, true)
}

func (s *Serv) init(service *Service, c context) func(*Service, bool) Service {

	var status Service
	var fallback *Real
	reals := map[IP4]*Real{}

	update := func(service *Service, fin bool) {
		if service != nil {

			status = *service

			for real, r := range service.Reals {
				if _, ok := reals[real]; ok {
					reals[real].Reconfigure(r)
				} else {
					reals[real] = StartReal(r, c, false)
				}
			}

			if service.Fallback {
				r := healthchecks.Real{Checks: service.FallbackChecks, RIP: c.vip}
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

	c.new_vip = false
	c.new_svc = false

	return func(service *Service, fin bool) Service {
		update(service, false)

		var healthy uint16

		ret := status
		ret.Healthy = false

		// copy reals to new slice that we can modify
		r := map[IP4]healthchecks.Real{}
		for k, v := range ret.Reals {

			if real, ok := reals[k]; ok {
				v.Probe = real.Status()

				if v.Probe.Passed {
					healthy++
				}
			} else {
				panic("probe function does not exist " + k.String())
			}

			r[k] = v
		}
		ret.Reals = r // write the slice to the returned object

		if fallback != nil {
			ret.FallbackProbe = fallback.Status()
		}

		if healthy >= ret.Minimum {
			ret.Healthy = true
		} else if fallback != nil {
			if ret.FallbackProbe.Passed {
				ret.Healthy = true
				ret.FallbackOn = true
			}
		}

		// call function to determine if leastcons should be enabled?
		// ret.Leastconns, ret.Weight = some_fn(status)
		//ret.Leastconns = 3
		//ret.Weight = 128

		update(nil, fin)

		return ret
	}
}

type Real struct {
	f func(*healthchecks.Real, bool) Probe
}

func StartReal(real healthchecks.Real, c context, local bool) *Real {
	return &Real{f: rip(real, c, local)}
}

func (r *Real) Close() {
	r.f(nil, true)
}

func (r *Real) Reconfigure(real healthchecks.Real) {
	r.f(&real, false)
}

func (r *Real) Status() Probe {
	return r.f(nil, false)
}

func rip(real healthchecks.Real, c context, local bool) func(*healthchecks.Real, bool) Probe {

	probe := Probe{Time: time.Now()}
	nat := c.vip

	if !local {
		nat = natify(c.base, real.NAT)
	}

	if c.new_vip {
		probe.Passed = false // new vip - start everything in down state to avoid uneccessary vip advert
	} else if c.new_svc {
		probe.Passed = true // new service on existing vip - start up to avoid killing vip
	} else if c.new_rip {
		probe.Passed = false // new rip on existsing svc - start down to avoid re-hash
	}

	var mutex sync.Mutex

	ch := checks(&probe, &mutex, nat, real.RIP, c.vip, c.l4, c.sock, real.Checks, c.log, c.notify)

	return func(ip *healthchecks.Real, fin bool) Probe {

		if ip != nil {
			ch <- ip.Checks
		}

		if fin {
			close(ch)
		}

		mutex.Lock()
		defer mutex.Unlock()
		return probe
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

func checks(probe *Probe, mutex *sync.Mutex, nat, rip, vip IP4, l4 L4, sock string, checks Checks, l types.Logger, notify chan bool) chan Checks {

	ch := make(chan Checks)

	go func() {

		var ok bool
		history := [5]bool{probe.Passed, probe.Passed, probe.Passed, probe.Passed, probe.Passed}

		t := time.NewTicker(2 * time.Second)
		defer t.Stop()

		for {
			select {
			case <-t.C:

				now := time.Now()
				history = rotate(history, probes(nat, sock, checks))

				mutex.Lock()
				last := probe.Passed
				probe.Duration = time.Now().Sub(now)
				probe.Passed = healthy(history)

				if probe.Passed != last {
					l.NOTICE("monitor", vip, l4, rip, nat, "went", probe.Passed)
					probe.Time = time.Now()
					if notify != nil {
						select {
						case notify <- probe.Passed:
						default:
						}
					}
				}
				mutex.Unlock()

			case checks, ok = <-ch:
				if !ok {
					return
				}
			}
		}
	}()

	return ch
}

func probes(nat IP4, socket string, checks Checks) bool {

	for _, c := range checks.Http {
		if !netns.Probe(socket, nat, "http", c) {
			return false
		}
	}

	for _, c := range checks.Https {
		if !netns.Probe(socket, nat, "https", c) {
			return false
		}
	}

	for _, c := range checks.Tcp {
		if !netns.Probe(socket, nat, "tcp", c) {
			return false
		}
	}

	for _, c := range checks.Syn {
		if !netns.Probe(socket, nat, "syn", c) {
			return false
		}
	}

	for _, c := range checks.Dns {
		if !netns.Probe(socket, nat, "dns", c) {
			return false
		}
	}

	return true
}
