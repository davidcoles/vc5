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
	//"fmt"
	"time"

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/core"
	"github.com/davidcoles/vc5/logger"
	//"github.com/davidcoles/vc5/probes"
	"github.com/davidcoles/vc5/stats"
	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type MAC = types.MAC
type VR = config.VR
type NI = config.NI

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
		nats := do_nats(conf.NAT)
		real := arp(conf.Real)
		vips := virtuals(conf.VIPs)

		for n := range c {
			real <- n.Real
			nats <- n.NAT
			vips <- n.VIPs
			bgp4 <- n.RHI
		}

		close(bgp4)
		time.Sleep(2 * time.Second)
		close(vips)
		close(real)
	}()
	return c
}

func do_nats(nats map[VR]NI) chan map[VR]NI {
	c := make(chan map[VR]NI, 1)
	c <- nats
	go func() {
		state := make(map[VR]NI)
		for nats = range c {
			defer func() {
				for k, v := range state {
					ctrl.DelNatVipRip(v.NAT, k.VIP, k.RIP)
				}
			}()

			for k, v := range nats {
				//if _, ok := state[k]; !ok {
				//	fmt.Println("ADDING", k, v.NAT)
				//}

				//var mac MAC
				//copy(mac[:], v.Info.Iface.HardwareAddr)
				ctrl.SetNatVipRip(v.NAT, k.VIP, k.RIP, v.Info.Source, v.Info.Iface.Name, v.Info.VLAN, v.Info.Iface.Index, v.Info.MAC)
			}

			for k, v := range state {
				if _, ok := nats[k]; !ok {
					//fmt.Println("DELETING", k, v.NAT)
					ctrl.DelNatVipRip(v.NAT, k.VIP, k.RIP)
				}
			}

			state = nats
		}
	}()
	return c
}

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
		count.Rx_pps = (count.Rx_packets - prev.Rx_packets) // uint64(interval)
		count.Rx_bps = (count.Rx_octets - prev.Rx_octets)   // uint64(interval)
		count.DEFCON = c.Defcon(0)
		counters <- count

		//if n%10 == 0 {
		//	fmt.Printf("%d pps, %d ns avg. latency\n", count.Pps, count.Latency)
		//s := fmt.Sprintf(">>> %d pps, %d ns avg. latency", count.Pps, count.Latency)
		//l.INFO(s)
		//}
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
