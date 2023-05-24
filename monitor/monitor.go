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
	"sync"
	"time"

	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/netns"
	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type MAC = types.MAC
type L4 = types.L4

type Checks = healthchecks.Checks
type Check = healthchecks.Check
type Metadata = healthchecks.Metadata
type Healthchecks = healthchecks.Healthchecks
type Service = healthchecks.Service
type Probe = healthchecks.Probe
type Virtual = healthchecks.Virtual
type Report = healthchecks.Healthchecks

type context struct {
	sock    string // UNIX domain docket to communicate with netns NAT server
	vip     IP4
	l4      L4
	log     types.Logger
	new_vip bool
	new_svc bool
	new_rip bool
	notify  chan bool
}

func ud(b bool) string {
	if b {
		return "UP"
	}

	return "DOWN"
}

func (m *Mon) manage(l types.Logger) {
	var changed bool

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer close(m.C)

	for {
		select {
		case h, ok := <-m.in: // new configuration
			if !ok {
				return
			}
			m.apply(h)     // apply the config
			changed = true // let downstream know of the change next tick

		case <-ticker.C: // notify downstream if changed
			if changed {
				select {
				default: // don't block
				case m.C <- m.status():
					changed = false
				}
			}

		case <-m.notify: // something changed
			changed = true
		}
	}
}

type Mon struct {
	fn     func(*healthchecks.Healthchecks, bool) Report
	C      chan healthchecks.Healthchecks
	in     chan *Healthchecks
	notify chan bool
}

func Monitor(h *Healthchecks, sock string, l types.Logger) (*Mon, Healthchecks) {
	m := &Mon{C: make(chan Healthchecks), in: make(chan *Healthchecks), notify: make(chan bool)}
	m.fn = m.monitor(h, sock, l)
	r := m.fn(nil, false)
	go m.manage(l)
	return m, r
}

func (m *Mon) Update(h *Healthchecks) {
	m.in <- h
}

func (m *Mon) status() Healthchecks {
	return m.fn(nil, false)
}

func (m *Mon) apply(h *Healthchecks) {
	m.fn(h, false)
}

func (m *Mon) Close() {
	m.fn(nil, true)
}

func (m *Mon) monitor(h *Healthchecks, sock string, l types.Logger) func(*Healthchecks, bool) Report {

	var status Healthchecks

	virts := map[IP4]*Virt{}

	update := func(h *Healthchecks, fin bool) {

		if h != nil {

			status = *h

			for vip, services := range h.Virtual {
				if v, ok := virts[vip]; ok {
					v.Reconfigure(services)
				} else {
					virts[vip] = StartVirt(services, context{vip: vip, sock: sock, log: l, notify: m.notify})
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

		r := status // take a new copy of the config root
		r.Virtual = map[IP4]Virtual{}

		for k, fn := range virts {
			v := fn.Status()
			r.Virtual[k] = v
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

	var was bool
	change := time.Now()

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

		if virt.Healthy != was {
			change = time.Now()
		}

		virt.Change = change

		was = virt.Healthy

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

	var was bool
	change := time.Now()

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

		if ret.Healthy != was {
			change = time.Now()
		}

		ret.Change = change

		was = ret.Healthy

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
		nat = real.NAT
	}

	// When:
	// * adding a new vip, all checks should start in down state to prevent traffic being sent to the LB
	// * adding a new service to an existing vip, service should start in "up" state to prevent vip being withdrawn (chaos)
	// * adding a new real to an existing service, host checks should start in "down" state to prevent hash being changed

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

		mutex.Lock()
		defer mutex.Unlock()

		if ip != nil {
			if ch != nil {
				ch <- ip.Checks
			} else {
				c.log.ERR("probe", "trying to send on closed channel")
			}
		}

		if fin {
			close(ch)
			ch = nil
		}

		//mutex.Lock()
		//defer mutex.Unlock()
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

	ch := make(chan Checks, 1000)

	go func() {

		var ok bool
		history := [5]bool{probe.Passed, probe.Passed, probe.Passed, probe.Passed, probe.Passed}

		t := time.NewTicker(2 * time.Second)
		defer t.Stop()

		for {
			select {
			case <-t.C:

				now := time.Now()
				//history = rotate(history, probes(nat, sock, checks))

				ok, msg := probes(nat, sock, checks)
				history = rotate(history, ok)

				mutex.Lock()
				last := probe.Passed
				probe.Duration = time.Now().Sub(now)
				probe.Passed = healthy(history)
				probe.Message = msg

				if probe.Passed != last {
					//l.NOTICE("monitor", vip, l4, rip, nat, "went", probe.Passed)
					l.NOTICE("monitor", fmt.Sprintf("Real server %s for %s:%s (NAT address %s) went %s: %s", rip, vip, l4, nat, ud(ok), msg))
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

func probes(nat IP4, socket string, checks Checks) (bool, string) {

	if nat.IsNil() {
		return false, "Internal error - NAT address is nil"
	}

	for _, c := range checks.HTTPS {
		if ok, msg := netns.Probe(socket, nat, "https", c); !ok {
			return false, "HTTPS probe failed: " + msg
		}
	}

	for _, c := range checks.HTTP {
		if ok, msg := netns.Probe(socket, nat, "http", c); !ok {
			return false, "HTTP probe failed: " + msg
		}
	}

	for _, c := range checks.TCP {
		if ok, msg := netns.Probe(socket, nat, "tcp", c); !ok {
			return false, "TCP probe failed: " + msg
		}
	}

	for _, c := range checks.SYN {
		if ok, msg := netns.Probe(socket, nat, "syn", c); !ok {
			return false, "SYN probe failed: " + msg
		}
	}

	for _, c := range checks.DNS {
		if ok, msg := netns.Probe(socket, nat, "dns", c); !ok {
			return false, "DNS probe failed: " + msg
		}
	}

	return true, "OK"
}
