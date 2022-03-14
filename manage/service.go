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

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/rendezvous"
	"github.com/davidcoles/vc5/types"
)

func service(s config.Service, w *sync.WaitGroup, l4 chan l4status_t) chan config.Service {
	c := make(chan config.Service)
	go func() {
		logs.DEBUG("Starting", s.String())

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
			sink <- types.Scounters{Delete: true, VIP: s.Vip, Port: s.Port, Protocol: s.Protocol}
			for _, v := range state {
				close(v.c)
			}

			select {
			case l4 <- l4status_t{l4: s.L4(), up: false}:
			case <-time.After(1 * time.Second):
			}

			wait := wait_channel(&wg)

		do_select:
			select {
			case <-status_c:
				goto do_select
			case <-wait:
			}

			logs.DEBUG("Quitting", s.String())
			w.Done()
		}()

		ticker := time.NewTicker(4 * time.Second)
		init_timer := time.NewTimer(10 * time.Second)

		var reconf bool = true
		var recalc bool = true
		var init bool = false
		var up bool
		var nalive int

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
						state[r.Rip] = &state_t{g: gen, c: real_ip(r, &wg, status_c, stats_c), r: r}
					}
				}

				for k, v := range state {
					if v.g != gen {
						close(v.c)
						delete(state, k)
					}
				}
			}

			if recalc {
				recalc = false
				var isup bool

				alive := make(map[[4]byte]uint16)

				for k, v := range state {
					if v.u {
						alive[k] = v.r.Index
					}
				}

				nalive = len(alive)

				if len(alive) >= int(s.Need) {
					isup = true
				} else {
					alive = make(map[[4]byte]uint16) // blank it
				}

				table, stats := rendezvous.RipIndex(alive)
				logs.DEBUG(s.String(), len(alive), table[0:32], stats)
				ctrl.SetBackendIdx(s.Vip, s.Port, bool(s.Protocol), table)

				if init && isup != up { // send new status
					l4 <- l4status_t{l4: s.L4(), up: isup}
					logs.NOTICE("Changed", s.String(), "to", updown(isup))
				}

				up = isup
			}

			if true { // send stats every time
				be := make(map[string]types.Counters)
				for k, v := range state {
					v.s.Up = v.u
					be[k.String()] = v.s
				}

				sc := types.Scounters{Name: s.Name, Description: s.Description, Up: up, Backends: be,
					VIP: s.Vip, Port: s.Port, Protocol: s.Protocol, Need: s.Need, Nalive: uint(nalive)}
				sc.Sum()
				sink <- sc // put in a select with timeout
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

			case <-init_timer.C:
				init = true
				l4 <- l4status_t{l4: s.L4(), up: up}
				logs.NOTICE("Starting", s.String(), "as", updown(up))

			case u := <-status_c:
				if v, ok := state[u.ip]; ok {
					v.u = u.up
				}
				recalc = true
				goto do_select

			case s := <-stats_c:
				if v, ok := state[s.Ip]; ok {
					v.s = s
				}
				goto do_select

			case <-ticker.C: // break out periodically to do stats/recalc
			}

		}
	}()
	return c
}
