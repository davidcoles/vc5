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
	"fmt"
	"time"

	"vc5/bgp4"
	"vc5/config"
)

type nlri_t struct {
	ip IP4
	up bool
}

var nlri_c chan nlri_t

func do_bgp(addr IP4, learn uint16, conf config.RHI) chan config.RHI {
	c := make(chan config.RHI)

	var gen uint64

	type state_t struct {
		peer *bgp4.BGP4
		done chan bool
		gen  uint64
	}

	var t uint16 = 10
	if learn > 0 {
		t = learn
	}

	nlri := make(map[IP4]bool)

	nlri_c = make(chan nlri_t, 1000)

	timer := time.NewTimer(time.Duration(t) * time.Second)
	state := make(map[string]state_t)
	start := make(chan bool)

	go func() {

		defer func() {
			for k, v := range state {
				fmt.Println("closing bgp", k)
				close(v.done)
			}
		}()

		for {
			for _, s := range conf.Peers {
				if v, ok := state[s]; !ok {
					done := make(chan bool)
					fmt.Println("starting bgp", s)
					peer := bgp4.BGP4Start(s, addr, conf.RouterId, conf.ASNumber, start, done)
					for k, v := range nlri {
						peer.NLRI([4]byte(k), v)
					}

					state[s] = state_t{peer: peer, done: done, gen: gen}
				} else {
					v.gen = gen
					state[s] = v
				}
			}

			for k, v := range state {
				if v.gen != gen {
					fmt.Println("closing bgp", k)
					close(v.done)
					delete(state, k)
				}
			}

			select {
			case r, ok := <-c:
				if !ok {
					fmt.Println("closing down bgp")
					return
				}
				conf = r
				gen++

			case <-timer.C:
				close(start)

			case n := <-nlri_c:
				nlri[n.ip] = n.up
				for _, v := range state {
					go v.peer.NLRI([4]byte(n.ip), n.up)
				}

			}
		}
	}()

	return c
}

func NLRI(ip IP4, up bool) {
	nlri_c <- nlri_t{ip: ip, up: up}
}
