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
	//"errors"
	//"net"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	//"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/monitor/healthchecks"
	//"github.com/davidcoles/vc5/monitor/netns"
	"github.com/davidcoles/vc5/types"
)

type Healthchecks = healthchecks.Healthchecks
type Counter = kernel.Counter

// A LoadBalancer defines the network parameters for operation of the
// load-balancing logic, such as what interfaces and driver
// modes to use.
type BYOB struct {

	// Logging interface to use for event reporting.
	Logger types.Logger
	report monitor.Report
	byolb  Balancer
	mutex  sync.Mutex
	update chan *healthchecks.Healthchecks
}

// Returns a map of active service statistics. A counter is returned
// for each four-tuple of virtual IP, backend IP, layer
// four protocol and port number (Target).
func (lb *BYOB) Stats() (kernel.Counter, map[kernel.Target]kernel.Counter) {
	//return lb.balancer.Global(), lb.balancer.Stats()
	lb.mutex.Lock()
	stats := lb.byolb.Stats(lb.report)
	lb.mutex.Unlock()

	return kernel.Counter{}, stats
}

// Status returns a Healthchecks object which is a copy of the current
// load-balancer configuration with backend server MAC addresses and
// healthcheck probe results, service and virtual IP status filled in.
func (lb *BYOB) Status() healthchecks.Healthchecks {
	lb.mutex.Lock()
	r := lb.report
	lb.mutex.Unlock()
	return r
}

// Cease all load-balancing functionality. Once called the
// LoadBalancer object must not be used.
func (lb *BYOB) Close() {
	close(lb.update)
}

// Replace the LoadBalancer configuration with hc. New VIPs, services
// and backend server will be added in a non-disruptive manner,
// existing elements will be unchanged and obsolete ones removed.
func (lb *BYOB) Update(hc *healthchecks.Healthchecks) {
	lb.update <- hc
}

// Initialse load-balancing functionality using address as the
// default IP address to source health probes from. The set of virtual
// IP addresses, layer 4 services and backend server IP addresses and
// healthcheck definitions is passed in hc.

// If all of the backend servers are in VLANs specified in the
// healthchecks configuration then address will not be used.
func (lb *BYOB) Start(balancer Balancer, hc *healthchecks.Healthchecks) error {

	if lb.Logger == nil {
		lb.Logger = &types.NilLogger{}
	}

	monitor, report := monitor.Monitor(hc, &checker2{}, lb.Logger)
	lb.report = report

	lb.update = make(chan *healthchecks.Healthchecks)

	balancer.Configure(lb.report)

	lb.byolb = balancer

	go lb.background(monitor, balancer)

	return nil
}

type Balancer interface {
	Configure(healthchecks.Healthchecks)
	Stats(healthchecks.Healthchecks) map[kernel.Target]kernel.Counter
	Close()
}

type checker2 struct {
}

func (c *checker2) Check(vip IP4, rip IP4, nat IP4, schema string, check healthchecks.Check) (bool, string) {
	switch schema {

	case "http":
		return httpget(schema, rip.String(), check)
	case "https":
		return httpget(schema, rip.String(), check)
	}

	return false, "not implemented"
}

func (lb *BYOB) background(monitor *monitor.Mon, balancer Balancer) {

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

var client *http.Client

func httpget(scheme, ip string, check healthchecks.Check) (bool, string) {

	if client == nil {

		transport := &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 2 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 1 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		}

		client = &http.Client{
			Timeout:   time.Second * 3,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	defer client.CloseIdleConnections()

	path := check.Path
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	port := check.Port
	if port == 0 {
		port = 80
	}

	url := fmt.Sprintf("%s://%s:%d/%s", scheme, ip, port, path)
	req, err := http.NewRequest("GET", url, nil)
	if check.Host != "" {
		req.Host = check.Host
	}

	resp, err := client.Do(req)

	if err != nil {
		return false, err.Error()
	}

	defer resp.Body.Close()

	ioutil.ReadAll(resp.Body)

	exp := int(check.Expect)

	if exp == 0 {
		exp = 200
	}

	return resp.StatusCode == exp, resp.Status
}
