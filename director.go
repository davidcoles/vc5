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
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/monitor/healthchecks"
	"github.com/davidcoles/vc5/types"
)

type Healthchecks = healthchecks.Healthchecks
type Counter = kernel.Counter
type Checker = monitor.Checker

type Balancer interface {
	Start(string, *healthchecks.Healthchecks) error
	Configure(*healthchecks.Healthchecks)
	Checker() monitor.Checker
	Status() healthchecks.Healthchecks
	Stats() (kernel.Counter, map[kernel.Target]kernel.Counter)
	Close()
}

type Director struct {
	Logger   types.Logger
	Balancer Balancer
	update   chan *healthchecks.Healthchecks
}

// Returns a map of active service statistics. A counter is returned
// for each four-tuple of virtual IP, backend IP, layer
// four protocol and port number (Target).
func (lb *Director) Stats() (kernel.Counter, map[kernel.Target]kernel.Counter) {
	return lb.Balancer.Stats()
}

// Status returns a Healthchecks object which is a copy of the current
// load-balancer configuration with backend server MAC addresses and
// healthcheck probe results, service and virtual IP status filled in.
func (lb *Director) Status() healthchecks.Healthchecks {
	return lb.Balancer.Status()
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

	monitor, report := monitor.Monitor(hc, lb.Balancer.Checker(), lb.Logger)

	lb.update = make(chan *healthchecks.Healthchecks)

	lb.Balancer.Start(ip, report.DeepCopy())

	go lb.background(monitor, lb.Balancer)

	return nil
}

func (lb *Director) background(monitor *monitor.Mon, balancer Balancer) {

	go func() {
		defer balancer.Close()
		for h := range monitor.C {
			lb.Logger.INFO("Director", "Monitor update")
			balancer.Configure(&h)
		}
	}()

	defer monitor.Close()
	for h := range lb.update {
		lb.Logger.INFO("Director", "Config update")
		monitor.Update(h)
	}

}
