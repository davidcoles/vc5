package vc5

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/monitor/healthchecks"
	"github.com/davidcoles/vc5/monitor/netns"
	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type L4 = types.L4
type Target = kernel.Target

// Generate a Healthchecks object from a Config
func Load(conf *config.Config) (*healthchecks.Healthchecks, error) {
	return healthchecks.Load(conf)
}

// Unmarshal a Config object from a JSON file. An internal
// LoadBalancer Healthchecks object can be generated from this
func LoadConf(file string) (*config.Config, error) {
	return config.Load(file)
}

// Start a healthcheck server which will listen for requests via the
// UNIX domain socket. This should be called by the executable spawned
// from the LoadBalancer.NetnsCommand[] setting, which will be run a
// different network namespace.
func NetnsServer(socket string) {
	netns.Server(socket, kernel.IP.String())
}

// A LoadBalancer defines the network parameters for operation of the
// load-balancing logic, such as what interfaces and driver
// modes to use.
type LoadBalancer struct {
	// DEFCON level at which to start the load-balancer; will default
	// to normal operation if left at 0.
	ReadinessLevel uint8

	// Network safety feature to use during testing; number of minutes
	// after which to disable the balance.r
	KillSwitch uint

	// Use native driver mode when attaching interfaces in XDP.
	Native bool

	// Treat VLANs as seperate interfaces, rather than tagging
	// ethernet frames. Not recommended for production - you should
	// use tagged VLANs wherever possible.
	MultiNIC bool

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
	report   monitor.Report
	mutex    sync.Mutex
	update   chan *healthchecks.Healthchecks
}

// Returns an array of packet counters. Each counter is the total
// number of packets received from sequential /20 subnets (4096 IP
// addresses per subnet); element 0 corresponds to 0.0.0.0/20, element
// 42929 corresponds to 10.123.16.0/20. This can be used to build a
// profile of client source addresses for reporting/visualisation or
// DDoS mitigation purposes. This is an expensive operation (may take
// over a second to complete) so you should rate-limit how often is it
// called.
func (lb *LoadBalancer) Prefixes() [1048576]uint64 {
	return lb.maps.ReadPrefixCounters()
}

// Returns a map of active service statistics. A counter is returned
// for each four-tuple of virtual IP, backend IP, layer
// four protocol and port number (Target).
func (lb *LoadBalancer) Stats() (kernel.Counter, map[kernel.Target]kernel.Counter) {
	return lb.balancer.Global(), lb.balancer.Stats()
}

// Status returns a Healthchecks object which is a copy of the current
// load-balancer configuration with backend server MAC addresses and
// healthcheck probe results, service and virtual IP status filled in.
func (lb *LoadBalancer) Status() healthchecks.Healthchecks {
	lb.mutex.Lock()
	r := lb.report
	lb.mutex.Unlock()
	return r
}

// Update readiness level. This enables various levels of DDoS
// mitigation.
func (lb *LoadBalancer) DEFCON(d uint8) uint8 {
	return lb.maps.DEFCON(d)
}

// Cease all load-balancing functionality. Once called the
// LoadBalancer object must not be used.
func (lb *LoadBalancer) Close() {
	close(lb.update)
	lb.netns.Close()
}

// Replace the LoadBalancer configuration with hc. New VIPs, services
// and backend server will be added in a non-disruptive manner,
// existing elements will be unchanged and obsolete ones removed.
func (lb *LoadBalancer) Update(hc *healthchecks.Healthchecks) {
	lb.update <- hc
}

// Initialse load-balancing functionality using address as the
// default IP address to source health probes from. The set of virtual
// IP addresses, layer 4 services and backend server IP addresses and
// healthcheck definitions is passed in hc.

// If all of the backend servers are in VLANs specified in the
// healthchecks configuration then address will not be used.
func (lb *LoadBalancer) Start(address string, hc *healthchecks.Healthchecks) error {

	ip := net.ParseIP(address)

	if ip == nil {
		return errors.New("Invalid IP address")
	}

	ip = ip.To4()

	if ip == nil {
		return errors.New("Not an IPv4 address")
	}

	l := lb.Logger

	if l == nil {
		l = &types.NilLogger{}
	}

	ns := &kernel.NetNS{}
	err := ns.Init()

	if err != nil {
		return err
	}

	lb.netns = ns

	var cleanup bool = true

	defer func() {
		if cleanup {
			ns.Close()
		}
	}()

	bond := lb.EgressInterface
	peth := lb.Interfaces
	native := lb.Native
	args := lb.NetnsCommand
	sock := lb.Socket

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

	lb.maps, err = kernel.Open(native, ns.IfA, ns.IfB, peth...)

	if err != nil {
		return err
	}

	err = ns.Open()

	if err != nil {
		return err
	}

	cleanup = false

	lb.maps.MODE(lb.MultiNIC)

	if lb.ReadinessLevel != 0 {
		lb.DEFCON(lb.ReadinessLevel)
	}

	go netns.Spawn(ns.NS, args...)

	nat := &kernel.NAT{
		Maps:          lb.maps,
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

	monitor, report := monitor.Monitor(hc2, sock, l)
	lb.report = report

	lb.balancer = lb.maps.Balancer(lb.report, l)

	lb.update = make(chan *healthchecks.Healthchecks)

	go lb.background(nat, monitor, lb.balancer)

	if lb.KillSwitch > 0 {
		// temporary auto kill switch
		go func() {
			for {
				time.Sleep(time.Duration(lb.KillSwitch) * time.Minute)
				lb.DEFCON(0)
			}
		}()
	}

	return nil
}

func (lb *LoadBalancer) background(nat *kernel.NAT, monitor *monitor.Mon, balancer *kernel.Balancer) {

	go func() {
		defer balancer.Close()
		for h := range monitor.C {
			log.Println("MONITOR update")
			lb.mutex.Lock()
			lb.report = *(h.DeepCopy())
			lb.mutex.Unlock()
			balancer.Configure(h)
		}
	}()

	go func() {
		defer monitor.Close()
		for h := range nat.C {
			log.Println("NAT update")
			monitor.Update(h)
		}
	}()

	defer nat.Close()
	for h := range lb.update {
		log.Println("CONF update")
		nat.Configure(h)
	}
}
