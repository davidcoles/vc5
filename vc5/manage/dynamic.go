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

	"vc5/config"
	"vc5/core"
	"vc5/logger"
	//"vc5/probes"
	"vc5/stats"
	"vc5/types"
)

type IP4 = types.IP4
type MAC = types.MAC

var ctrl *core.Control
var webserver *stats.SServer
var logs *logger.Logger
var sink chan types.Scounters

func updown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

func Bootstrap(conf *config.Config, ctl *core.Control, l *logger.Logger, ws *stats.SServer) chan *config.Config {

	ctrl = ctl
	logs = l

	webserver = ws

	go global_stats(ctrl, webserver.Counters(), logs)

	sink = webserver.Scounters()

	c := make(chan *config.Config)

	go func() {
		bgp4 := do_bgp(conf.Address, conf.Learn, conf.RHI)
		//real := reals(conf.Info)
		real := arp(conf.Real)
		vips := virtuals(conf.VIPs)

		for n := range c {
			real <- n.Real
			vips <- n.VIPs
			bgp4 <- n.RHI
		}

		close(vips)
		close(real)
		close(bgp4)
	}()
	return c
}

func get_tx(ip IP4, nics []types.NIC) uint8 {
	for i, n := range nics {
		if n.IPNet.Contains(ip[:]) {
			return uint8(i)
		}
	}
	return 0
}

/*
func reals(reals map[IP4]config.Info) chan map[IP4]config.Info {
	c := make(chan map[IP4]config.Info)

	go func() {

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for r, i := range reals {
			ctrl.SetBackendRec(r, MAC{}, i.VLAN, i.Index, 0)
			ctrl.SetRip(r)
		}

		for {
			select {
			case <-ticker.C:
			case r, ok := <-c:
				if !ok {
					return
				}

				for r, i := range r {
					if _, ok := reals[r]; !ok {
						ctrl.SetBackendRec(r, MAC{}, i.VLAN, i.Index, 0)
						ctrl.SetRip(r)
					}
				}

				reals = r

			}

			for r, i := range reals {
				go func(r IP4, i config.Info) {
					probes.Ping(r)
					time.Sleep(2 * time.Second)

					if ctrl != nil {
						m := ctrl.ReadMAC(r)
						if m != nil {
							ctrl.SetBackendRec(r, *m, i.VLAN, i.Index, 0)
						}
					}

				}(r, i)
			}
		}
	}()
	return c
}
*/

func global_stats(c *core.Control, counters chan types.Counters, l *logger.Logger) {
	var prev types.Counters
	var avg []uint64

	c.GlobalStats(true)

	for n := 0; ; n++ {
		time.Sleep(1 * time.Second)

		count := c.GlobalStats(false)

		latency := count.Fp_time
		if count.Fp_count > 0 {
			latency /= count.Fp_count
		}

		avg = append(avg, latency)
		for len(avg) > 4 {
			avg = avg[1:]
		}

		latency = 0

		if len(avg) > 0 {
			for _, v := range avg {
				latency += v
			}
			latency /= uint64(len(avg))
		}

		count.Latency = latency
		count.Pps = (count.Rx_packets - prev.Rx_packets) // uint64(interval)
		counters <- count

		if n%10 == 0 {
			fmt.Printf("%d pps, %d ns avg. latency\n", count.Pps, count.Latency)
			//s := fmt.Sprintf(">>> %d pps, %d ns avg. latency", count.Pps, count.Latency)
			//l.INFO(s)
		}
		prev = count
	}
}

type Split struct {
	C        chan bool
	done     chan bool
	timer    *time.Timer
	ticker   *time.Ticker
	duration time.Duration
}

func NewSplit(initial time.Duration, subsequent time.Duration) *Split {
	s := &Split{C: make(chan bool), done: make(chan bool), timer: time.NewTimer(initial), duration: subsequent}
	go func() {

		defer func() {
			if s.ticker != nil {
				s.ticker.Stop()
			}
			s.timer.Stop()
		}()

		select {
		case <-s.timer.C:
			select {
			case s.C <- true:
			case <-s.done:
				return
			}
		case <-s.done:
			return
		}

		s.ticker = time.NewTicker(s.duration)

		for {
			select {
			case <-s.ticker.C:
				select {
				case s.C <- true:
				case <-s.done:
					return
				}
			case <-s.done:
				return
			}
		}
	}()
	return s
}

func (s *Split) Stop() {
	close(s.done)
}

//func ping(ip IP4) {
//	probes.Ping(ip)
//}
