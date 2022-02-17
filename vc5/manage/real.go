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
	"vc5/probes"
	"vc5/types"
)

//func applyRip(r config.Real, wg *sync.WaitGroup, status_c chan status_t, stats_c chan stats_t) chan config.Real {
func applyRip(r config.Real, wg *sync.WaitGroup, status_c chan status_t, stats_c chan types.Counters) chan config.Real {
	c := make(chan config.Real)

	go func() {

		l4 := L4{Port: r.Port, Udp: r.Udp}
		logs.DEBUG("Starting", r.Vip, l4, r.Rip)

		// this *may* be a new real IP, wait a few seconds for MAC to be discovered
		time.Sleep(3 * time.Second)

		done := make(chan bool)

		var concurrent uint64
		ctrl.VipRipPortCounters(r.Vip, r.Rip, r.Port, true)
		ctrl.SetNatVipRip(r.Nat, r.Vip, r.Rip, r.Src, r.Iface, r.VLAN, r.IfIndex, r.IfMAC) // this can occur for multiple ports! need NVR manager
		updates := ctrl.VipRipPortConcurrents2(r.Vip, r.Rip, r.Port, done)

		status_timer := time.NewTicker(5 * time.Second) // run healthchecks every 5s
		stats_timer := time.NewTicker(1 * time.Second)  // update stats every 1s

		defer func() {
			logs.DEBUG("Quiting", r.Vip, l4, r.Rip)
			close(done)
			status_timer.Stop()
			stats_timer.Stop()
			wg.Done()
		}()

		var up bool
		var init bool

		for {
			s := doChecks(r)

			// force a status upate after first check
			if !init {
				up = !s
				init = true
			}

			if up != s {
				select {
				case status_c <- status_t{ip: r.Rip, up: s}:
					up = s
				case <-time.After(1 * time.Second):
					panic("timeout")
				}
				logs.NOTICE("Changed", r.Vip, l4, r.Rip, "to", updown(up))
			}

		do_select:
			select {
			case concurrent = <-updates:
				goto do_select
			case <-stats_timer.C:
				// lookup and send stats with timeout

				select {
				//case stats_c <- stats_t{}:
				case stats_c <- ctrl.VipRipPortCounters2(r.Vip, r.Rip, r.Port, false, concurrent):
				case <-time.After(1 * time.Second):
					panic("timeout")
				}
				goto do_select

			case <-status_timer.C:
			case n, ok := <-c:
				if !ok {
					return
				}
				r = n

			}

		}
	}()

	return c
}

func doChecks(real config.Real) bool {

	for _, c := range real.Syn {
		if !probes.SYNCheck(real.Nat, c.Port) {
			return false
		}
	}

	for _, c := range real.Tcp {
		if !probes.TCPCheck(real.Nat, c.Port) {
			return false
		}
	}

	for _, c := range real.Http {
		if s, _ := probes.HTTPCheck(real.Nat, c.Port, c.Path, int(c.Expect), c.Host); !s {
			return false
		}
	}

	for _, c := range real.Https {
		if s, _ := probes.HTTPSCheck(real.Nat, c.Port, c.Path, int(c.Expect), c.Host); !s {
			return false
		}
	}

	return true
}
