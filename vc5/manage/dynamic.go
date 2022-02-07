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
	"vc5/core"
	"vc5/logger"
	"vc5/probes"
	"vc5/rendezvous"
	"vc5/stats"
	"vc5/types"
)

var ctrl *core.Control
var peers *bgp4.Peers
var webserver *stats.SServer
var logs *logger.Logger

type rstats = types.Counters
type IP4 = types.IP4
type MAC = types.MAC

type status struct {
	ip IP4
	pt uint16
	up bool
	co types.Counters
}
type serv struct {
	ip IP4
	pt uint16
	ud bool
}

func stats_sink() chan types.Scounters {
	c := make(chan types.Scounters, 100)
	go func() {
		for x := range c {
			webserver.Scounters() <- x
			if false {
				fmt.Println("COUNTERS", x.Name)
			}
		}
	}()
	return c
}

func ApplyConfig(conf *config.Config, ctr *core.Control, l *logger.Logger) chan *config.Config {
	ctrl = ctr
	logs = l

	ws := ":80"
	if conf.Webserver != "" {
		ws = conf.Webserver
	}
	webserver = stats.Server(ws, logs, ctrl)

	go global_stats(ctrl, webserver.Counters(), logs)

	s := webserver.Scounters()

	if len(conf.RHI.Peers) > 0 {
		peers = bgp4.Manager(ctrl.IPAddr(), conf.RHI.RouterId, conf.RHI.ASNumber, conf.RHI.Peers)

		go func() {
			if conf.Learn > 0 {
				time.Sleep(time.Duration(conf.Learn) * time.Second)
			}
			peers.Start()
		}()
	}

	c := applyConfig(conf, s)

	for k, v := range conf.Reals {
		fmt.Println(k, v)
	}

	return c
}

func applyRHI(rhi config.RHI, learn uint16) chan config.RHI {
	peers = bgp4.Manager(ctrl.IPAddr(), rhi.RouterId, rhi.ASNumber, rhi.Peers)
	r := make(chan config.RHI)

	go func() {
		if learn > 0 {
			time.Sleep(time.Duration(learn) * time.Second)
		}

		peers.Start()

		for _ = range r {
		}

		peers.Close()
	}()

	return r
}

func applyConfig(conf *config.Config, stats chan types.Scounters) chan *config.Config {
	confc := make(chan *config.Config)

	go func() {

		reals := applyPing(conf.Reals)
		services := applyServices(stats)
		//rhi := applyRHI(conf.RHI, conf.Learn)

		services <- conf.Services

		defer func() {
			//close(rhi)
			peers.Close()
			time.Sleep(5 * time.Second)
			close(services)
			close(reals)
		}()

		for c := range confc {
			reals <- c.Reals
			services <- c.Services
			//rhi <- c.RHI
		}
	}()
	return confc
}

func applyPing(reals map[IP4]uint16) chan map[IP4]uint16 {
	c := make(chan map[IP4]uint16)

	go func() {

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for r, i := range reals {
			ctrl.SetBackendRec(r, MAC{}, 0, i)
			ctrl.SetRip(r)
		}

		for {
			select {
			case <-ticker.C:
			case r, ok := <-c:
				if !ok {
					return
				}
				reals = r
				for r, i := range reals {
					ctrl.SetBackendRec(r, MAC{}, 0, i)
					ctrl.SetRip(r)
				}
			}

			for r, i := range reals {
				go func(r IP4, i uint16) {
					var v uint16
					probes.Ping(r)
					time.Sleep(2 * time.Second)

					//fmt.Println(r)

					if ctrl != nil {
						m := ctrl.ReadMAC(r)
						if m != nil {
							ctrl.SetBackendRec(r, *m, v, i)
							//fmt.Println(r, m)
						}
					}

				}(r, i)
			}
		}
	}()
	return c
}

func applyServices(stats chan types.Scounters) chan []config.Service {
	c := make(chan []config.Service)
	go applyServices_(c, stats)
	return c
}
func applyServices_(c chan []config.Service, stats chan types.Scounters) {

	type V struct {
		g uint64
		c chan config.Service
	}

	var gen uint64
	current := make(map[string]V)

	vip_status := make(chan status)
	go func() {
		vp := make(map[serv]bool)
		vb := make(map[IP4]bool)
		for s := range vip_status {
			fmt.Println("VIP STATUS", s.ip, s.pt, s.up)
			vp[serv{ip: s.ip, pt: s.pt}] = s.up

			tmp := make(map[IP4]bool)

			for k, v := range vp {
				if _, ok := tmp[k.ip]; ok {
					if !v {
						tmp[k.ip] = false
					}
				} else {
					tmp[k.ip] = v
				}
			}

			vb = tmp

			for k, v := range vb {
				fmt.Println("VIP", k, v)
				peers.NLRI(k, v)
			}
		}
	}()

	for ss := range c {
		fmt.Println("CONFIG CHANGE")
		gen++

		for _, s := range ss {

			n := fmt.Sprintf("%s:%d", s.Vip, s.Port)

			if v, ok := current[n]; !ok {
				current[n] = V{g: gen, c: make(chan config.Service)}
				go applyService(s, current[n].c, stats, vip_status)
			} else {
				v.g = gen
				current[n] = v
				current[n].c <- s
			}
		}

		for k, v := range current {
			if v.g != gen {
				close(v.c)
				delete(current, k)
			}
		}
	}

	fmt.Println("services quitting")

	defer func() {
		for _, v := range current {
			close(v.c)
		}
	}()
}

func applyService(srv config.Service, c chan config.Service, stats chan types.Scounters, vip_status chan status) {

	name := fmt.Sprintf("%s:%d:tcp", srv.Vip, srv.Port)
	fmt.Println("starting service", name)

	// create service in XDP

	statuses := make(chan status)
	statistics := make(chan rstats)

	var gen uint64
	type V struct {
		g uint64
		c chan config.Real
		u bool
		s rstats
		i uint16
	}

	current := make(map[IP4]V)

	ticker := time.NewTicker(5 * time.Second)

	defer func() {
		fmt.Println("quitting service", name)

		ticker.Stop()
		for _, v := range current {
			close(v.c)
		}

		// delete service from XDP
	}()

	var nup uint
	var up bool
	var apply bool = true
	var recalculate bool

	for {
		if apply {
			apply = false
			gen++
			fmt.Println("re-applying service", name)
			recalculate = true

			for _, r := range srv.Rip {
				k := r.Rip

				if v, ok := current[k]; !ok {
					current[k] = V{g: gen, c: applyReal(r, statuses, statistics), u: false, i: r.Idx}
				} else {
					v.g = gen
					current[k] = v
					current[k].c <- r
				}

			}

			for k, v := range current {
				if v.g != gen {
					close(v.c)
					delete(current, k)
				}
			}

		}

		if recalculate {
			recalculate = false

			ips := make(map[[4]byte]uint16)
			up = nup >= srv.Need

			for k, v := range current {
				if up && v.u {
					ips[k] = v.i
				}
			}

			x, s := rendezvous.RipIndex(ips)
			fmt.Println(srv.Vip, srv.Port, s, x[0:32])
			ctrl.SetBackendIdx(srv.Vip, srv.Port, x)

			vip_status <- status{ip: srv.Vip, pt: srv.Port, up: up}
			fmt.Println("SERVICE", name, "is currently", up, "with", nup)
		}

		be := make(map[string]rstats)
		for k, v := range current {
			v.s.Up = v.u
			be[k.String()] = v.s
		}

		sc := types.Scounters{Name: srv.Name, Description: srv.Description, Sname: name, Up: up, Backends: be}
		sc.Sum()
		stats <- sc

	do_select:
		select {
		case <-ticker.C: // periodically break out of select to recaclulate if needed
		case f := <-statuses:
			if v, ok := current[f.ip]; ok {
				//fmt.Println(f.ip, "changed to", f.up)
				v.u = f.up
				current[f.ip] = v
				recalculate = true
			}

			nup = 0
			for _, v := range current {
				if v.u {
					nup++
				}
			}

			goto do_select

		case b := <-statistics:
			if v, ok := current[b.Ip]; ok {
				//fmt.Println(b.ip, "stats", n)
				v.s = b
				current[b.Ip] = v
			}
			goto do_select

		case s, ok := <-c:
			if !ok {
				return
			}
			srv = s
			apply = true
		}

	}
}

func applyReal(real config.Real, s chan status, stats chan rstats) chan config.Real {
	c := make(chan config.Real)
	go _applyReal(real, c, s, stats)
	return c
}

func _applyReal(real config.Real, c chan config.Real, s chan status, stats chan rstats) {
	fmt.Println("starting real", real.Rip, real)

	if ctrl != nil {
		ctrl.SetNatVipRip(real.Nat, real.Vip, real.Rip, real.Src, real.Iface, real.VLan)
	}

	ds := do_stats(real, stats)
	rc := runChecks(real, s)

	defer func() {
		close(ds)
		close(rc)
		//ctrl.DelNatVipRip(real.Nat, real.Vip, real.Rip)
	}()

	for x := range c {
		fmt.Println("re-applying real", real.Rip)
		rc <- x
	}

	fmt.Println("quitting real", real.Rip)
}

func do_stats(real config.Real, stats chan rstats) chan bool {
	done := make(chan bool)
	ctrl.VipRipPortCounters(real.Vip, real.Rip, real.Port, true)
	updates := ctrl.VipRipPortConcurrents2(real.Vip, real.Rip, real.Port, done)

	var concurrent uint64

	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(1 * time.Second):
				stats <- ctrl.VipRipPortCounters2(real.Vip, real.Rip, real.Port, false, concurrent)
			case concurrent = <-updates:
			}
		}
	}()
	return done
}

func runChecks(real config.Real, s chan status) chan config.Real {
	c := make(chan config.Real)
	go func() {
		fmt.Println("starting checks for", real.Rip, real)

		var up bool // starts as down

		ticker := time.NewTicker(5 * time.Second)
		defer func() {
			ticker.Stop()
			s <- status{ip: real.Rip, up: false}
		}()

		for {
			select {
			case <-ticker.C:
			case r, ok := <-c:
				if !ok {
					fmt.Println("quiting checks for", real.Rip)
					return
				}
				fmt.Println("re-applying checks for", real.Rip)
				real = r
			}

			var ok bool = true

			for _, c := range real.Http {
				if s, _ := probes.HTTPCheck(real.Nat, c.Port, c.Path, int(c.Expect), c.Host); !s {
					ok = false
				}
			}
			for _, c := range real.Https {
				if s, _ := probes.HTTPSCheck(real.Nat, c.Port, c.Path, int(c.Expect), c.Host); !s {
					ok = false
				}
			}
			for _, c := range real.Tcp {
				if !probes.TCPCheck(real.Nat, c.Port) {
					ok = false
				}
			}
			for _, c := range real.Syn {
				if !probes.SYNCheck(real.Nat, c.Port) {
					ok = false
				}
			}

			if ok != up {
				up = ok
				fmt.Println("REAL STATE CHANGE", real.Rip, up)
				s <- status{ip: real.Rip, up: up}
			}
		}
	}()
	return c
}

func global_stats(c *core.Control, cchan chan types.Counters, l *logger.Logger) {
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
		//c.Counters() <- count
		cchan <- count

		if n%10 == 0 {
			fmt.Printf("%d pps, %d ns avg. latency\n", count.Pps, count.Latency)
			//s := fmt.Sprintf(">>> %d pps, %d ns avg. latency", count.Pps, count.Latency)
			//l.INFO(s)
		}
		prev = count
	}
}
