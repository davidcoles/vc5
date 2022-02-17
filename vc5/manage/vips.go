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
	"vc5/rendezvous"
	"vc5/types"
)

type L4 = types.L4
type services = map[IP4]map[L4]config.Service

func applyVips(s services) chan services {
	c := make(chan services)

	go func() {

		var g uint64

		type state_t struct {
			g uint64
			c chan map[L4]config.Service
		}

		state := make(map[IP4]*state_t)

		var wg sync.WaitGroup

		logs.DEBUG("Starting services")
		defer func() {
			for _, v := range state {
				close(v.c)
			}
			wg.Wait()
			logs.DEBUG("Quitting services")
		}()

		for {
			for k, v := range s {
				if x, ok := state[k]; ok {
					x.g = g
					x.c <- v
					//state[k] = x
				} else {
					wg.Add(1)
					state[k] = &state_t{g: g, c: applyVip(k, v, &wg)}
				}
			}

			for k, v := range state {
				if v.g != g {
					close(v.c)
					delete(state, k)
				}
			}

			select {
			case n, ok := <-c:
				if !ok {
					return
				}
				s = n
				g++
			}
		}
	}()

	return c
}

func applyVip(vip IP4, s map[L4]config.Service, w *sync.WaitGroup) chan map[L4]config.Service {
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

		ticker := time.NewTicker(2 * time.Second)

		var wg sync.WaitGroup

		defer func() {
			NLRI(vip, false)
			time.Sleep(2 * time.Second)
			ticker.Stop()
			for _, v := range state {
				close(v.c)
			}
			wg.Wait()
			w.Done()
			logs.DEBUG("Quitting", vip)
		}()

		var reconf bool = true
		var up bool

		for {
			// run a ping

			if reconf {
				reconf = false
				for k, v := range s {
					if x, ok := state[k]; ok {
						x.g = g
						x.c <- v
						//current[k] = x
					} else {
						wg.Add(1)
						state[k] = &state_t{g: g, c: applySvc(vip, k, v, &wg, l4status_c), u: true}
						// start initially as true so as to not bring down other services on same VIP
					}
				}

				for k, v := range state {
					if v.g != g {
						close(v.c)
						delete(state, k)
					}
				}
			}

		do_select:
			select {
			case n, ok := <-c:
				if !ok {
					return
				}
				s = n
				g++
				reconf = true

			case s := <-l4status_c:
				if v, ok := state[s.l4]; ok {
					v.u = s.up
					//current[s.l4] = v
				}
				goto do_select

			case <-ticker.C:
			}

			// recalculate VIP status + send if necc
			var ok bool = true
			for _, v := range state {
				if !v.u {
					ok = false
				}
			}

			if up != ok {
				up = ok
				NLRI(vip, up)
			}

		}
	}()
	return c
}

type status_t struct {
	ip IP4
	up bool
}

type l4status_t struct {
	l4 L4
	up bool
}

func applySvc(vip IP4, svc L4, s config.Service, w *sync.WaitGroup, l4 chan l4status_t) chan config.Service {
	c := make(chan config.Service)
	go func() {
		logs.DEBUG("Starting", vip, svc)

		name := vip.String() + ":" + svc.String()

		var wg sync.WaitGroup

		type state_t struct {
			g uint64
			c chan config.Real
			u bool
			r config.Real
			s types.Counters
		}

		var gen uint64

		state := make(map[IP4]*state_t)

		status_c := make(chan status_t, 1000)
		stats_c := make(chan types.Counters, 1000)

		defer func() {
			sink <- types.Scounters{Sname: name, Delete: true}
			for _, v := range state {
				close(v.c)
			}

			select {
			case l4 <- l4status_t{l4: svc, up: false}:
			case <-time.After(1 * time.Second):
			}
			wg.Wait()
			logs.DEBUG("Quitting", vip, svc)
			w.Done()
		}()

		ticker := time.NewTicker(4 * time.Second)

		var reconf bool = true
		var recalc bool = true
		var init bool

		var up bool

		for {
			if reconf {
				reconf = false
				recalc = true
				for _, r := range s.Rip {
					if v, ok := state[r.Rip]; ok {
						v.g = gen
						v.c <- r
						v.r = r
						//current[r.Rip] = v
					} else {
						wg.Add(1)
						state[r.Rip] = &state_t{g: gen, c: applyRip(r, &wg, status_c, stats_c), r: r}
					}
				}

				for k, v := range state {
					if v.g != gen {
						close(v.c)
						delete(state, k)
					}
				}
			}

		do_select:
			select {
			case n, ok := <-c:
				if !ok {
					return
				}
				s = n
				gen++
				reconf = true

			case u := <-status_c:
				if v, ok := state[u.ip]; ok {
					// update status
					v.u = u.up
					//current[u.ip] = v
				}
				recalc = true
				goto do_select

			case s := <-stats_c:
				if v, ok := state[s.Ip]; ok {
					v.s = s
					//current[s.Ip] = v
				}
				goto do_select

			case <-ticker.C: // break out to do any recalc
			}

			if true {
				be := make(map[string]types.Counters)
				for k, v := range state {
					v.s.Up = v.u
					be[k.String()] = v.s
				}

				sc := types.Scounters{Name: s.Name, Description: s.Description, Sname: name, Up: up, Backends: be}
				sc.Sum()
				sink <- sc
			}

			if recalc {
				recalc = false
				var isup bool

				alive := make(map[[4]byte]uint16)

				for k, v := range state {
					if v.u {
						alive[k] = v.r.Idx
					}
				}

				if len(alive) >= int(s.Need) {
					isup = true
				} else {
					alive = make(map[[4]byte]uint16) // blank it
				}

				table, _ := rendezvous.RipIndex(alive)
				logs.DEBUG(s.Vip, s.Port, len(alive), table[0:32])
				ctrl.SetBackendIdx(s.Vip, s.Port, s.Udp, table)

				// force update on first run - should have had time to do health checks
				if isup != up || !init {
					// send new status
					init = true
					up = isup
					l4 <- l4status_t{l4: svc, up: up}
					logs.NOTICE("Changed", vip, svc, "to", updown(up))
				}
			}

		}
	}()
	return c
}
