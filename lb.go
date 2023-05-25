package vc5

import (
	//"fmt"
	"errors"
	"log"
	"net"
	//"os/exec"
	"sync"
	"time"

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/monitor/healthchecks"
	"github.com/davidcoles/vc5/monitor/netns"
	"github.com/davidcoles/vc5/types"
)

const NAMESPACE = "vc5"
const VC5A = "vc5a"
const VC5B = "vc5b"

var vc5aip [4]byte = [4]byte{10, 255, 255, 253}
var vc5bip IP4 = IP4{10, 255, 255, 254}

type IP4 = types.IP4
type L4 = types.L4
type NET = types.NET
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
	netns.Server(sock, vc5bip.String())
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
	//clean(VC5A, NAMESPACE)
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

	go netns.Spawn(NAMESPACE, args...)

	nat := &kernel.NAT{
		Maps: lb.maps,

		DefaultIP:     ip,
		PhysicalMAC:   bondmac,
		PhysicalIndex: bondidx,

		//VC5aIf:  ns.Index,
		//VC5aIP:  ns.IPA(),
		//VC5bIP:  ns.IPB(),
		//VC5aMAC: ns.MacA,
		//VC5bMAC: ns.MacB,

		NetNS: ns,

		Logger: l,
	}

	hc2, err := nat.NAT(hc)

	if err != nil {
		return err
	}

	monitor, report := monitor.Monitor(hc2, sock, l)
	lb.report = report
	//lb.monitor, lb.report = monitor.Monitor(hc2, sock, l)

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

/**********************************************************************/
/*
type NetNS struct {
	Range      [2]byte
	A, B       string
	MacA, MacB [6]byte
	Index      int
	NS         string
}

func (n *NetNS) Init() error {
	if n.Range[0] == 0 {
		n.Range[0] = 10
		n.Range[1] = 255
	}

	n.NS = NAMESPACE
	n.A = "vc5a"
	n.B = "vc5b"

	setup1(n.A, n.B)

	iface, err := net.InterfaceByName(n.A)
	if err != nil {
		return err
	}
	copy(n.MacA[:], iface.HardwareAddr[:])

	n.Index = iface.Index

	iface, err = net.InterfaceByName(n.B)
	if err != nil {
		return err
	}
	copy(n.MacB[:], iface.HardwareAddr[:])

	return nil
}

func (n *NetNS) Open() error {
	setup2(n.NS, n.A, n.B, n.IPA(), n.IPB())
	return nil
}

func (n *NetNS) Close()   { clean(n.A, n.NS) }
func (n *NetNS) IPA() IP4 { return IP4{n.Range[0], n.Range[1], 255, 253} }
func (n *NetNS) IPB() IP4 { return IP4{n.Range[0], n.Range[1], 255, 254} }

func clean(if1, ns string) {
	script1 := `
    ip link del ` + if1 + ` >/dev/null 2>&1 || true
    ip netns del ` + ns + ` >/dev/null 2>&1 || true
`
	exec.Command("/bin/sh", "-e", "-c", script1).Output()
}

func setup1(if1, if2 string) {
	script1 := `
ip link del ` + if1 + ` >/dev/null 2>&1 || true
ip link add ` + if1 + ` type veth peer name ` + if2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		log.Fatal(err)
	}
}

func setup2(ns, if1, if2 string, i1, i2 IP4) {
	ip1 := i1.String()
	ip2 := i2.String()
	cb := i1
	cb[2] = 0
	cb[3] = 0
	cbs := cb.String()

	script1 := `
ip netns del ` + ns + ` >/dev/null 2>&1 || true
ip l set ` + if1 + ` up
ip a add ` + ip1 + `/30 dev ` + if1 + `
ip netns add ` + ns + `
ip link set ` + if2 + ` netns ` + ns + `
ip netns exec vc5 /bin/sh -c "ip l set ` + if2 + ` up && ip a add ` + ip2 + `/30 dev ` + if2 + ` && ip r replace default via ` + ip1 + ` && ip netns exec ` + ns + ` ethtool -K ` + if2 + ` tx off"
ip r replace ` + cbs + `/16 via ` + ip2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		log.Fatal(err)
	}
}
*/

func (lb *LoadBalancer) Load(conf *config.Config) (*healthchecks.Healthchecks, error) {
	return healthchecks.Load(conf)
}
