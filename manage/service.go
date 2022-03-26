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

type state_t struct {
	generation uint64
	channel    chan config.Real
	up         bool
	real       config.Real
	stats      types.Counters
}

type service_state map[IP4]*state_t

func service(service config.Service, tuple Thruple, w *sync.WaitGroup, l4 chan l4status_t) chan config.Service {
	c := make(chan config.Service, 1)
	c <- service
	go func() {
		logs.DEBUG("Starting", tuple.String())

		var wg sync.WaitGroup
		var generation uint64

		state := make(map[IP4]*state_t)
		status_c := make(chan status_t, 1000)
		stats_c := make(chan types.Counters, 1000)

		defer func() {
			ctrl.DelBackendIdx(tuple.IP, tuple.Port, bool(tuple.Protocol))

			sink <- types.Scounters{Delete: true, VIP: tuple.IP, Port: tuple.Port, Protocol: tuple.Protocol}
			for _, v := range state {
				close(v.channel)
			}

			select {
			case l4 <- l4status_t{l4: tuple.L4(), up: false}:
			case <-time.After(1 * time.Second):
			}

			wait := wait_channel(&wg)

		do_select:
			select {
			case <-status_c:
				goto do_select
			case <-wait:
			}

			logs.DEBUG("Quitting", tuple.String())
			w.Done()
		}()

		split := NewSplit(10*time.Second, 4*time.Second)

		//var init bool

		table, up, alive := backend_mapping(service, tuple, nil)
		ctrl.SetBackendIdx(tuple.IP, tuple.Port, bool(tuple.Protocol), table, false, 0, 0)
		up = true // assume service is up iniially

		var recalcuate bool

		for {
			var ok bool
			select {
			case service, ok = <-c:
				if !ok {
					return
				}
				generation++
				state = reconfigure(service, tuple, state, generation, &wg, status_c, stats_c)
				recalcuate = true
				continue

			case u := <-status_c:
				if v, ok := state[u.ip]; ok {
					v.up = u.up
				}
				recalcuate = true
				continue

			case s := <-stats_c:
				if v, ok := state[s.Ip]; ok {
					v.stats = s
				}
				continue

			case <-split.C:
			}

			var leastconns uint8
			var weight uint8

			if service.LeastConns {
				leastconns, weight = least_conns(tuple, state)
			}

			was := up

			if recalcuate {
				recalcuate = false
				table, up, alive = backend_mapping(service, tuple, state)
			}

			// just update this every time - it's only once every 4 seconds
			ctrl.SetBackendIdx(tuple.IP, tuple.Port, bool(tuple.Protocol), table, service.Sticky, leastconns, weight)

			if up != was {
				l4 <- l4status_t{l4: tuple.L4(), up: up}
				logs.NOTICE("Changed", tuple.String(), "to", updown(up))
			}

			sink <- service_counters(service, tuple, state, up, alive)
		}
	}()
	return c
}

func reconfigure(s config.Service, t Thruple, state map[IP4]*state_t, g uint64, w *sync.WaitGroup,
	status_c chan status_t, stats_c chan types.Counters) map[IP4]*state_t {

	for _, r := range s.Rip {
		if v, ok := state[r.Rip]; ok {
			v.generation = g
			v.channel <- r
			v.real = r
		} else {
			w.Add(1)
			state[r.Rip] = &state_t{generation: g, channel: real_ip(r, t, w, status_c, stats_c), real: r}
		}
	}

	for k, v := range state {
		if v.generation != g {
			close(v.channel)
			delete(state, k)
		}
	}

	return state
}

func backend_mapping(s config.Service, t Thruple, state map[IP4]*state_t) ([8192]byte, bool, uint) {

	var isup bool

	alive := make(map[[4]byte]uint16)

	for k, v := range state {
		if v.up {
			alive[k] = v.real.Index
		}
	}

	if len(alive) >= int(s.Need) {
		isup = true
	} else {
		alive = nil
	}

	table, stats := rendezvous.RipIndex(alive)
	logs.DEBUG("Backend", t.String(), len(alive), table[0:32], stats)
	return table, isup, uint(len(alive))
}

func least_conns(tuple types.Thruple, state map[IP4]*state_t) (uint8, uint8) {

	var leastconns uint8
	var weight uint64 = 255
	var average uint64
	var nservers uint64
	var minimum uint64
	var server IP4

	for _, v := range state {
		if v.up {
			average += v.stats.Rx_bps
			nservers++
		}
	}

	if nservers == 0 {
		return 0, 0
	}

	average /= nservers

	// is there a particularly unloaded server?
	for k, v := range state {
		if v.up && (minimum == 0 || v.stats.Rx_bps < minimum) {
			minimum = v.stats.Rx_bps
			leastconns = uint8(v.real.Index)
			server = k
		}
	}

	// don't kick in unless average > 1Mbps and server has less than 80% of average
	if ((average * 8) > 1000000) && (minimum < ((average * 4) / 5)) {
		logs.NOTICE("Least connections adjustment", tuple.String(), server, "bps/average:", minimum, "/", average)

		weight = (255 * minimum) / average
		if weight > 255 {
			weight = 255
		}

		return leastconns, 255 - uint8(weight)
	}

	return 0, 0
}

func service_counters(s config.Service, t types.Thruple, state service_state, up bool, alive uint) types.Scounters {

	be := make(map[string]types.Counters)
	for k, v := range state {
		v.stats.Up = v.up
		be[k.String()] = v.stats
	}

	sc := types.Scounters{Name: s.Name, Description: s.Description, Up: up, Backends: be,
		VIP: t.IP, Port: t.Port, Protocol: t.Protocol, Need: s.Need, Nalive: alive}
	sc.Sum()
	return sc
}
