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
	"sync"

	//"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/monitor/healthchecks"
	"github.com/davidcoles/vc5/types"
)

type Healthchecks = healthchecks.Healthchecks
type Counter = kernel.Counter

type Director struct {

	// Logging interface to use for event reporting.
	Logger   types.Logger
	report   monitor.Report
	Balancer Balancer
	mutex    sync.Mutex
	update   chan *healthchecks.Healthchecks
}

// Returns a map of active service statistics. A counter is returned
// for each four-tuple of virtual IP, backend IP, layer
// four protocol and port number (Target).
func (lb *Director) Stats() (kernel.Counter, map[kernel.Target]kernel.Counter) {
	//return lb.byolb.Global(), lb.bbyolb.Stats()
	lb.mutex.Lock()
	global, stats := lb.Balancer.Stats(lb.report)
	lb.mutex.Unlock()

	return global, stats
}

// Status returns a Healthchecks object which is a copy of the current
// load-balancer configuration with backend server MAC addresses and
// healthcheck probe results, service and virtual IP status filled in.
func (lb *Director) Status() healthchecks.Healthchecks {
	lb.mutex.Lock()
	r := lb.report
	lb.mutex.Unlock()
	return r
}

// Cease all load-balancing functionality. Once called the
// LoadBalancer object must not be used.
func (lb *Director) Close() {
	close(lb.update)
}

// Replace the LoadBalancer configuration with hc. New VIPs, services
// and backend server will be added in a non-disruptive manner,
// existing elements will be unchanged and obsolete ones removed.
func (lb *Director) Update(hc *healthchecks.Healthchecks) {
	lb.update <- hc
}

// Initialse load-balancing functionality using address as the
// default IP address to source health probes from. The set of virtual
// IP addresses, layer 4 services and backend server IP addresses and
// healthcheck definitions is passed in hc.

// If all of the backend servers are in VLANs specified in the
// healthchecks configuration then address will not be used.
//func (lb *Director) Start(ip string, hc *healthchecks.Healthchecks, balancer Balancer) error {
func (lb *Director) Start(ip string, hc *healthchecks.Healthchecks) error {

	if lb.Logger == nil {
		lb.Logger = &types.NilLogger{}
	}

	probes := &monitor.Probes{}
	probes.Start(ip)

	monitor, report := monitor.Monitor(hc, probes, lb.Logger)
	lb.report = report

	lb.update = make(chan *healthchecks.Healthchecks)

	lb.Balancer.Configure(lb.report)

	go lb.background(monitor, lb.Balancer)

	return nil
}

type Balancer interface {
	Configure(healthchecks.Healthchecks)
	Stats(healthchecks.Healthchecks) (kernel.Counter, map[kernel.Target]kernel.Counter)
	Close()
}

func (lb *Director) background(monitor *monitor.Mon, balancer Balancer) {

	go func() {
		defer balancer.Close()
		for h := range monitor.C {
			lb.Logger.INFO("LoadBalancer", "Monitor update")
			lb.mutex.Lock()
			lb.report = *(h.DeepCopy())
			lb.mutex.Unlock()
			balancer.Configure(h)
		}
	}()

	defer monitor.Close()
	for h := range lb.update {
		lb.Logger.INFO("LoadBalancer", "Config update")
		monitor.Update(h)
	}

}
