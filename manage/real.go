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
	"sync"
	"time"

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/probes"
	"github.com/davidcoles/vc5/types"
)

type Thruple = types.Thruple

func real_ip(real config.Real, service Thruple, wg *sync.WaitGroup, status_c chan status_t, stats_c chan types.Counters) chan config.Real {
	c := make(chan config.Real)

	go func() {

		history := []bool{false, false, true, true, true} // need 3/5 - first real check will determine the state

		svc := service.String()
		logs.DEBUG("Starting", svc, real.Rip)

		// this *may* be a new real IP, wait a few seconds for MAC to be discovered
		time.Sleep(3 * time.Second)

		done := make(chan bool)

		var concurrent uint64
		old := ctrl.VipRipPortCounters(service.IP, real.Rip, service.Port, true, 0)

		updates := ctrl.VipRipPortConcurrents(service.IP, real.Rip, service.Port, done)

		status_timer := time.NewTicker(5 * time.Second) // run healthchecks every 5s
		stats_timer := time.NewTicker(1 * time.Second)  // update stats every 1s

		defer func() {
			logs.DEBUG("Quitting", svc, real.Rip)
			close(done)
			status_timer.Stop()
			stats_timer.Stop()
			wg.Done()
		}()

		var state bool
		var init bool

		for {
			history = append(history, doChecks(real, state))

			for len(history) > 5 {
				history = history[1:]
			}

			var failed int
			for _, v := range history {
				if !v {
					failed++
				}
			}

			s := true
			if failed > 1 {
				s = false
			}

			if state != s || !init { // force a status upate after first check
				select {
				case status_c <- status_t{ip: real.Rip, up: s}:
					state = s
					init = true
				case <-time.After(1 * time.Second):
					// we don't update state here to cause a retry of the state change next time round
				}
				logs.NOTICE("Changed", svc, real.Rip, "to", updown(state))
			}

		do_select:
			select {
			case concurrent = <-updates:
				goto do_select
			case <-stats_timer.C:
				// lookup and send stats with timeout
				stats := ctrl.VipRipPortCounters(service.IP, real.Rip, service.Port, false, concurrent)
				stats.PerSec(old)
				old = stats
				select {
				case stats_c <- stats:
				case <-time.After(1 * time.Second):
				}
				goto do_select

			case <-status_timer.C:
			case r, ok := <-c:
				if !ok {
					return
				}
				real = r
			}

		}
	}()

	return c
}

func doChecks(real config.Real, was bool) bool {
	// fail fast
	if mac := ctrl.ReadMAC(real.Rip); mac == nil {
		return false
	}

	for _, c := range real.Syn {
		if s, e := probes.SYNCheck(real.Nat, c.Port); !s {
			if was {
				fmt.Println("syn", real, e)
			}
			return false
		}
	}

	for _, c := range real.Tcp {
		if s, e := probes.TCPCheck(real.Nat, c.Port); !s {
			if was {
				fmt.Println("tcp", real, e)
			}
			return false
		}
	}

	for _, c := range real.Http {
		if s, e := probes.HTTPCheck(real.Nat, c.Port, c.Path, int(c.Expect), c.Host); !s {
			if was {
				fmt.Println("http", real, e)
			}
			return false
		}
	}

	for _, c := range real.Https {
		if s, e := probes.HTTPSCheck(real.Nat, c.Port, c.Path, int(c.Expect), c.Host); !s {
			if was {
				fmt.Println("https", real, e)
			}
			return false
		}
	}

	return true
}
