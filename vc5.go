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
	"errors"
	"net"
	"sync"
	"time"

	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/monitor/healthchecks"
	"github.com/davidcoles/vc5/netns"
	"github.com/davidcoles/vc5/types"
)

// A VC5 defines the network parameters for operation of the
// load-balancing logic, such as what interfaces and driver
// modes to use.
type VC5 struct {
	// DEFCON level at which to start the load-balancer; will default
	// to normal operation if left at 0.
	ReadinessLevel uint8

	// Use native driver mode when attaching interfaces in XDP.
	Native bool

	// Treat VLANs as seperate interfaces, rather than tagging
	// ethernet frames. Not recommended for production - you should
	// use tagged VLANs wherever possible.
	MultiNIC bool

	// When true, the shared flow map will be used to check for
	// untracked flows which may hae migrated from other server in a
	// cluster. This mitigates agains flows being dropped because the
	// pool of beackend servers has changed since the flow began.
	Distributed bool

	// UNIX domain socket to use for initiating backend
	// healthchecks. The healtchecks are sources from a virtual
	// interface in a seperate network namespace - this socket is used
	// to communicate with the process running there.
	Socket string

	// Command to run to create the isolated healthcheck process. This
	// can be used to pass the UNIX domain socket to an executable
	// which will run NetnsServer().
	NetnsCommand []string

	// Array of one or more physical interfaces (eg.: eth0, enp130s0f0) to load with
	// the XDP/eBPF load-balancing logic.
	Interfaces []string

	// In the case of a bonded network device, the physical interfaces
	// (eg.: enp130s0f0, enp130s0f1) sould be declared in the
	// Interfaces field, and the name of the virtual device (bond0)
	// should be specified here. This will ensure that outgoing
	// healthcheck probes are set out from an active member of the link aggregation group.
	EgressInterface string

	// Logging interface to use for event reporting.
	Logger types.Logger

	balancer *kernel.Balancer
	maps     *kernel.Maps
	netns    *kernel.NetNS
	report   *monitor.Report
	mutex    sync.Mutex
	update   chan *healthchecks.Healthchecks
	checker  monitor.Checker
}

// Submit an array of bool elements, each corresponding to a /20 IPv4
// prefix. A true value will cause packets with a source address
// withing the prefix to be dropped.
func (v *VC5) BlockList(list [1048576]bool) {
	v.balancer.BlockList(list)
}

func (v *VC5) NoBlockList() {
	v.balancer.NoBlockList()
}

// Returns an array of packet counters. Each counter is the total
// number of packets received from sequential /20 subnets (4096 IP
// addresses per subnet); element 0 corresponds to 0.0.0.0/20, element
// 42929 corresponds to 10.123.16.0/20. This can be used to build a
// profile of client source addresses for reporting/visualisation or
// DDoS mitigation purposes. This is an expensive operation (may take
// over a second to complete) so you should rate-limit how often is it
// called.
func (v *VC5) Prefixes() [1048576]uint64 {
	return v.maps.ReadPrefixCounters()
}

// Poll the flow queue for state records which can be shared with
// other nodes in a cluster to preserve connections when failing over
// between nodes.
func (v *VC5) FlowQueue() []byte {
	return v.balancer.FlowQueue()
}

// Write state records retrieved from a node's flow queue into the
// kernel.
func (v *VC5) StoreFlow(fs []byte) {
	v.balancer.StoreFlow(fs)
}

// Update readiness level. This enables various levels of DDoS
// mitigation.
func (v *VC5) DEFCON(d uint8) uint8 {
	return v.maps.DEFCON(d)
}

// Initialse load-balancing functionality using address as the
// default IP address to source health probes from. The set of virtual
// IP addresses, layer 4 services and backend server IP addresses and
// healthcheck definitions is passed in hc.

// If all of the backend servers are in VLANs specified in the
// healthchecks configuration then address will not be used.
func (v *VC5) start(address string, hc *healthchecks.Healthchecks) error {

	if v.Socket == "" {
		return errors.New("No socket given")
	}

	//client := &netns.Client{Path: v.Socket}
	client := netns.NewClient(v.Socket)

	v.checker = &checker{client: client}

	ip := net.ParseIP(address)

	if ip == nil {
		return errors.New("Invalid IP address")
	}

	ip = ip.To4()

	if ip == nil {
		return errors.New("Not an IPv4 address")
	}

	l := v.Logger

	if l == nil {
		l = &types.NilLogger{}
	}

	ns := &kernel.NetNS{}
	err := ns.Init()

	if err != nil {
		return err
	}

	v.netns = ns

	var cleanup bool = true

	defer func() {
		if cleanup {
			ns.Close()
		}
	}()

	bond := v.EgressInterface
	peth := v.Interfaces
	native := v.Native
	args := v.NetnsCommand

	var bondidx int
	var bondmac [6]byte

	if bond != "" {
		iface, err := net.InterfaceByName(bond)
		if err != nil {
			return err
		}
		bondidx = iface.Index
		copy(bondmac[:], iface.HardwareAddr[:])
	} else {
		iface, err := net.InterfaceByName(peth[0])
		if err != nil {
			return err
		}
		bondidx = iface.Index
		copy(bondmac[:], iface.HardwareAddr[:])
	}

	v.maps, err = kernel.Open(native, ns.IfA, ns.IfB, peth...)

	if err != nil {
		return err
	}

	err = ns.Open()

	if err != nil {
		return err
	}

	cleanup = false

	v.maps.MultiNIC(v.MultiNIC)
	v.maps.Distributed(v.Distributed)

	if v.ReadinessLevel != 0 {
		v.DEFCON(v.ReadinessLevel)
	}

	if len(args) > 0 {
		go netns.Spawn(ns.NS, args...)
	}

	if v.Native {
		l.NOTICE("lb", "Waiting for NIC to quiesce")
		time.Sleep(15 * time.Second)
	}

	nat := &kernel.NAT{
		Maps:          v.maps,
		DefaultIP:     IP4{ip[0], ip[1], ip[2], ip[3]},
		PhysicalMAC:   bondmac,
		PhysicalIndex: bondidx,
		NetNS:         ns,
		Logger:        l,
	}

	hc2, err := nat.NAT(hc)

	if err != nil {
		return err
	}

	//monitor, report := monitor.Monitor(hc2, &checker{socket: sock}, l)
	v.report = hc2

	v.balancer = v.maps.Balancer(*v.report, l)

	v.update = make(chan *healthchecks.Healthchecks)

	go v.background(nat, v.balancer)

	return nil
}

func (lb *VC5) background(nat *kernel.NAT, balancer *kernel.Balancer) {

	go func() {
		defer balancer.Close()
		for h := range nat.C {
			lb.Logger.INFO("VC5", "NAT update")
			lb.mutex.Lock()
			lb.report = h.DeepCopy()
			lb.mutex.Unlock()
			balancer.Configure(*h)
		}
	}()

	defer nat.Close()
	for h := range lb.update {
		lb.Logger.INFO("VC5", "Config update")
		nat.Configure(h)
	}
}

/********************************************************************************/

// Status returns a Healthchecks object which is a copy of the current
// load-balancer configuration with backend server MAC addresses and
// healthcheck probe results, service and virtual IP status filled in.
func (v *VC5) Status() healthchecks.Healthchecks {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	r := v.report.DeepCopy()
	return *r
}

// Returns a map of active service statistics. A counter is returned
// for each four-tuple of virtual IP, backend IP, layer
// four protocol and port number (Target).
func (v *VC5) Stats() (kernel.Counter, map[kernel.Target]kernel.Counter) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	return v.balancer.Global(), v.balancer.Stats()
}

// Cease all load-balancing functionality. Once called the
// VC5 object must not be used.
func (v *VC5) Close() {
	close(v.update)
	v.netns.Close()
}

func (v *VC5) Configure(h *healthchecks.Healthchecks) {
	v.update <- h
}

func (v *VC5) Checker() monitor.Checker {
	//return &checker{socket: v.Socket}
	return v.checker
}

func (v *VC5) Start(address string, hc *healthchecks.Healthchecks) error {
	return v.start(address, hc)
}

/********************************************************************************/
type checker struct {
	//nat    *kernel.NAT
	client *netns.Client
}

// func (c *checker) Socket() string { return c.socket }
func (c *checker) Socket() string { return c.client.Path() }
func (c *checker) Check(vip IP4, rip IP4, check healthchecks.Check) (bool, string) {
	//	return netns.Probe(c.socket, kernel.LookupNAT(vip, rip), check)
	ip := kernel.LookupNAT(vip, rip)
	return c.client.Probe(ip, check)
}

// Start a healthcheck server which will listen for requests via the
// UNIX domain socket. This should be called by the executable spawned
// from the LoadBalancer.NetnsCommand[] setting, which will be run a
// different network namespace.
func NetnsServer(socket string) {
	netns.Server(socket, kernel.IP.String())
}
