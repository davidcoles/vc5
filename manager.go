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

package vc5

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/bgp"
	"github.com/davidcoles/cue/mon"
)

type Manager struct {
	Config   *Config
	Director *cue.Director
	Balancer Balancer
	Pool     *bgp.Pool
	Logs     *Sink

	mutex    sync.Mutex
	services Services
	summary  Summary
	vip      map[netip.Addr]State
	rib      []netip.Addr
	asn      uint16
	mp       bool
}

func (m *Manager) Manage(notifier mon.Notifier, prober mon.Prober, routerID [4]byte, asn uint16, mp bool, done chan bool) error {

	m.Director = &cue.Director{}

	if notifier != nil {
		m.Director.Notifier = notifier
	}

	if prober != nil {
		m.Director.Prober = prober
	}

	m.asn = asn
	m.mp = mp

	m.Pool = bgp.NewPool(routerID, m.Config.Bgp(asn, mp), nil, m.Logs.Sub("bgp"))

	if m.Pool == nil {
		return fmt.Errorf("BGP pool fail")
	}

	if err := m.Director.Start(m.Config.Parse()); err != nil {
		return err
	}

	start := time.Now()
	F := "vc5"

	m.vip = map[netip.Addr]State{}

	//var rib []netip.Addr
	//var summary Summary

	var old map[Instance]Stats
	m.services, old, _ = ServiceStatus(m.Config, m.Balancer, m.Director, nil)

	//vipmap := VipMap(nil) // test, but need to move vip management into man lb library

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			m.mutex.Lock()
			m.summary.Update(m.Balancer.Summary(), start)
			m.services, old, m.summary.Current = ServiceStatus(m.Config, m.Balancer, m.Director, old)
			m.mutex.Unlock()
			select {
			case <-ticker.C:
			case <-done:
				return
			}
		}
	}()

	go func() { // advertise VIPs via BGP
		timer := time.NewTimer(m.Config.Learn * time.Second)
		ticker := time.NewTicker(5 * time.Second)
		services := m.Director.Status()

		defer func() {
			ticker.Stop()
			timer.Stop()
			m.Pool.RIB(nil)
			time.Sleep(2 * time.Second)
			m.Pool.Close()
		}()

		var initialised bool
		for {
			select {
			case <-ticker.C: // check for matured VIPs
				//m.mutex.Lock()
				//vipmap = VipLog(director.Status(), vipmap, config.Priorities(), logs)
				//m.mutex.Unlock()

			case <-m.Director.C: // a backend has changed state
				m.mutex.Lock()
				services = m.Director.Status()
				m.Balancer.Configure(services)
				m.mutex.Unlock()
			case <-done: // shuting down
				return
			case <-timer.C:
				//logs.NOTICE(F, KV{"event": "Learn timer expired"})
				//logs.NOTICE(F, KV{"event.action": "learn-timer-expired"})
				m.Logs.Alert(NOTICE, F, "learn-timer-expired", KV{}, "Learn timer expired")
				initialised = true
			}

			m.mutex.Lock()
			m.vip = VipState(services, m.vip, m.Config.Priorities(), m.Logs)
			m.rib = AdjRIBOut(m.vip, initialised)
			m.mutex.Unlock()

			m.Pool.RIB(m.rib)
		}
	}()

	return nil
}

func (m *Manager) Configure(config *Config) {
	m.mutex.Lock()
	m.mutex.Unlock()
	m.Director.Configure(config.Parse())
	m.Pool.Configure(config.Bgp(m.asn, m.mp))
	m.Logs.Configure(config.Logging_())
	m.Config = config
}

func (m *Manager) Cue() ([]byte, error) {
	m.mutex.Lock()
	m.mutex.Unlock()
	return json.MarshalIndent(m.Director.Status(), " ", " ")
}

func (m *Manager) JSONStatus() ([]byte, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return JSONStatus(m.summary, m.services, m.vip, m.Pool, m.rib, m.Logs.Stats())
}

//func Prometheus(p string, services Services, summary Summary, vips map[netip.Addr]State) []string {
func (m *Manager) Prometheus(s string) []string {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return Prometheus(s, m.services, m.summary, m.vip)
}
