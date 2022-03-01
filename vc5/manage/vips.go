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

package manage

import (
	"sync"
	"time"

	"vc5/config"
	"vc5/types"
)

type L4 = types.L4
type services = map[IP4]map[L4]config.Service

type status_t struct {
	ip IP4
	up bool
}

type l4status_t struct {
	l4 L4
	up bool
}

func wait_channel(wg *sync.WaitGroup) chan bool {
	c := make(chan bool)
	go func() {
		wg.Wait()
		close(c)
	}()
	return c
}

func virtuals(s services) chan services {
	c := make(chan services)

	go func() {

		var g uint64

		type state_t struct {
			g uint64
			c chan map[L4]config.Service
			u bool
		}

		state := make(map[IP4]*state_t)

		status_c := make(chan status_t, 1000)

		var wg sync.WaitGroup

		logs.DEBUG("Starting services")
		defer func() {
			for _, v := range state {
				close(v.c)
			}

			wait := wait_channel(&wg)

		do_select:
			select {
			case <-status_c:
				goto do_select
			case <-wait:
			}

			logs.DEBUG("Quitting services")
		}()

		//var reconfigure bool = true

		reconfigure := func(s services) {
			g++
			for k, v := range s {
				if x, ok := state[k]; ok {
					x.g = g
					x.c <- v
				} else {
					wg.Add(1)
					state[k] = &state_t{g: g, c: virtual(k, v, status_c, &wg)}
				}
			}

			for k, v := range state {
				if v.g != g {
					close(v.c)
					delete(state, k)
				}
			}
		}

		reconfigure(s)

		for {
			m := make(map[string]bool)
			for k, v := range state {
				m[k.String()] = v.u
			}
			webserver.VIPs() <- m

			select {
			case s := <-status_c:
				if v, ok := state[s.ip]; ok {
					v.u = s.up
				}

			case n, ok := <-c:
				if !ok {
					return
				}
				reconfigure(n)
			}
		}
	}()

	return c
}

func virtual(vip IP4, s map[L4]config.Service, vip_c chan status_t, w *sync.WaitGroup) chan map[L4]config.Service {
	c := make(chan map[L4]config.Service)
	go func() {
		logs.DEBUG("Starting", vip)

		var g uint64

		type state_t struct {
			g uint64
			c chan config.Service
			u bool
		}

		l4status_c := make(chan l4status_t, 1000)

		state := make(map[L4]*state_t)
		split := NewSplit(10*time.Second, 2*time.Second)

		var wg sync.WaitGroup

		defer func() {
			advertise(vip, false)

			vip_c <- status_t{ip: vip, up: false}

			split.Stop()

			for _, v := range state {
				close(v.c)
			}

			wait := wait_channel(&wg)

			for {
				select {
				case <-l4status_c:
				case <-wait:
					w.Done()
					logs.DEBUG("Quitting", vip)
					return
				}
			}
		}()

		reconfigure := func(s map[L4]config.Service) {
			g++
			for k, v := range s {
				if x, ok := state[k]; ok {
					x.g = g
					x.c <- v
				} else {
					wg.Add(1)
					state[k] = &state_t{g: g, c: service(v, &wg, l4status_c), u: true}
					// start initially as up so as to not bring down other services on same VIP
				}
			}

			for k, v := range state {
				if v.g != g {
					close(v.c)
					delete(state, k)
				}
			}
		}

		var up bool = false
		recalculate := func() {
			var ok bool = true
			for _, v := range state {
				if !v.u {
					ok = false
				}
			}
			if ok != up {
				up = ok
				vip_c <- status_t{ip: vip, up: up}
				advertise(vip, up)
			}
		}

		reconfigure(s)

		for {
			select {
			case n, ok := <-c:
				if !ok {
					return
				}
				reconfigure(n)

			case s := <-l4status_c:
				if v, ok := state[s.l4]; ok {
					v.u = s.up
				}

			case <-split.C:
				recalculate()
			}
		}
	}()
	return c
}
