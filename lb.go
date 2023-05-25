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
type Status = monitor.Report

func Load(conf *config.Config) (*healthchecks.Healthchecks, error) {
	return healthchecks.Load(conf)
}

func (lb *LoadBalancer) LoadConf(file string) (*config.Config, error) {
	return config.Load(file)
}

func LoadConf(file string) (*config.Config, error) {
	return config.Load(file)
}

func NetnsServer(sock string) {
	netns.Server(sock, kernel.IP.String())
}

type LoadBalancer struct {
	ReadinessLevel  uint8
	KillSwitch      uint
	Native          bool
	MultiNIC        bool
	Socket          string
	NetnsCommand    []string
	Interfaces      []string
	EgressInterface string
	Logger          types.Logger

	balancer *kernel.Balancer
	maps     *kernel.Maps
	report   monitor.Report
	mutex    sync.Mutex
	netns    kernel.NetNS

	update chan *healthchecks.Healthchecks
}

func (lb *LoadBalancer) Prefixes() [kernel.PREFIXES]uint64 {
	return lb.maps.ReadPrefixCounters()
}

func (lb *LoadBalancer) Stats() (kernel.Counter, map[kernel.Target]kernel.Counter) {
	return lb.balancer.Global(), lb.balancer.Stats()
}

func (lb *LoadBalancer) Status() monitor.Report {
	lb.mutex.Lock()
	r := lb.report
	lb.mutex.Unlock()
	return r
}

func (lb *LoadBalancer) DEFCON(d uint8) uint8 {
	return lb.maps.DEFCON(d)
}

func (lb *LoadBalancer) Close() {
	close(lb.update)
	lb.netns.Close()
}

func (lb *LoadBalancer) Update(hc *healthchecks.Healthchecks) {
	lb.update <- hc
}

func (lb *LoadBalancer) Start(address string, hc *healthchecks.Healthchecks) error {

	ipaddr := net.ParseIP(address)

	if ipaddr == nil {
		return errors.New("Invalid IP address")
	}

	ip4 := ipaddr.To4()

	if ip4 == nil {
		return errors.New("Not an IPv4 address")
	}

	ip := IP4{ip4[0], ip4[1], ip4[2], ip4[3]}

	l := lb.Logger

	if l == nil {
		l = &types.NilLogger{}
	}

	ns := kernel.NetNS{}
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

	lb.maps, err = kernel.Open(native, ns.A, ns.B, peth...)

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
		DefaultIP:     ip,
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

func (lb *LoadBalancer) Load(conf *config.Config) (*healthchecks.Healthchecks, error) {
	return healthchecks.Load(conf)
}
