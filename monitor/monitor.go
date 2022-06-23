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
	"os/exec"
	"time"

	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type L4 = types.L4

type Checks = config2.Checks
type Check = config2.Check

type Backend = healthchecks.Backend
type Metadata = healthchecks.Metadata
type Reals map[uint16]Real
type Real = healthchecks.Real
type Service_ = healthchecks.Service_
type Virtual_ = healthchecks.Virtual_
type Healthchecks = healthchecks.Healthchecks

type context struct {
	vip IP4
	l4  L4
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

func Monitor(h *Healthchecks) func(*Healthchecks, bool) Report {

	x := map[IP4]func(*Virtual_, bool) Virtual{}
	backends := map[uint16]Backend{}

	update := func(h *Healthchecks, fin bool) {

		if h != nil {

			backends = h.Backends

			for vip, services := range h.Virtuals {
				if fn, ok := x[vip]; ok {
					fn(&services, false) // update sub-tree
				} else {
					x[vip] = virtual(&services, context{vip: vip})
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
			all = append(all, v.IP)
		}

		m := healthchecks.Macs(all)

		r.Backends = map[uint16]Backend{}
		for k, v := range backends {

			r.Backends[k] = Backend{IP: v.IP, MAC: m[v.IP]}
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
					x[s] = service_(&v, context{vip: c.vip, l4: s})
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

func service_(service *Service_, c context) func(*Service_, bool) Status {

	x := map[uint16]func(*Real, bool) bool{}
	var m Metadata

	update := func(service *Service_, fin bool) {
		if service != nil {

			m = service.Metadata

			for real, r := range service.Reals {
				if _, ok := x[real]; ok {
					x[real](&r, false)
				} else {
					x[real] = rip(&r, c)
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

func rip(r *Real, c context) func(*Real, bool) bool {

	x := *r

	var up bool

	done := make(chan bool)
	go foobar(done, &up, x.NAT, x.RIP)
	//fmt.Println(c, r.RIP)

	return func(ip *Real, fin bool) bool {
		if fin {
			close(done)
		}

		return up
	}
}

func foobar(d chan bool, up *bool, n uint16, x IP4) {
	//fmt.Println("!!!!!!!", probe(1, Check{Port: 80, Path: "/alive", Host: "foo.bar.baz"}))

	last := false

	for {
		select {
		case <-time.After(2 * time.Second):

			fmt.Println(">>>", n, x, last)

			//fmt.Println("WAIT", x)
			*up = probe(n, Check{Port: 80, Path: "/alive", Host: "foo.bar.baz"})

			if *up != last {
				fmt.Println(n, x, "went", *up)
			}

			last = *up

		case <-d:
			//fmt.Println("DONE", x)
			return
		}
	}
}

func probe(n uint16, c Check) bool {
	//ip netns exec vc5 /bin/bash -c 'curl -f http://10.255.0.1:8080/ && echo ok'

	if n == 0 || c.Port == 0 {
		return false
	}

	hl := htons(n)
	var nat IP4
	nat[0] = 10
	nat[1] = 255
	nat[2] = hl[0]
	nat[3] = hl[1]

	cmd := []string{"netns", "exec", "vc5", "curl", "-f", "-m", "1"}

	if c.Host != "" {
		cmd = append(cmd, "-H", "Host: "+c.Host)
	}

	url := fmt.Sprintf("http://%s:%d/%s", nat.String(), c.Port, c.Path)

	//fmt.Println(n, c, url)

	cmd = append(cmd, url)

	ret, err := exec.Command("/usr/sbin/ip", cmd...).Output()

	if false {
		fmt.Println(string(ret), err, cmd)
	}

	if err != nil {
		//fmt.Println(nat, err)
		//panic("dfdfdfd")
		return false
	}

	return true
}

func htons(p uint16) [2]byte {
	var hl [2]byte
	hl[0] = byte(p >> 8)
	hl[1] = byte(p & 0xff)
	return hl
}
