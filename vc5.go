package vc5

import (
	//"fmt"
	//"log"
	//"net"
	//"os/exec"
	//"sync"
	//"time"

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/core"
	"github.com/davidcoles/vc5/logger"
	"github.com/davidcoles/vc5/manage"
	"github.com/davidcoles/vc5/probes"
	"github.com/davidcoles/vc5/stats"
	"github.com/davidcoles/vc5/types"

	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/lb"
	//"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/netns"
)

const NAMESPACE = "vc5"
const VC5A = "vc5a"
const VC5B = "vc5b"

var vc5aip [4]byte = [4]byte{10, 255, 255, 253}
var vc5bip IP4 = IP4{10, 255, 255, 254}

type Control = core.Control
type IP4 = types.IP4
type L4 = types.L4
type NET = types.NET
type Target = kernel.Target

//type Status = monitor.Report

func Net(s string) (NET, error) {
	return types.Net(s)
}

const FLOW_STATE = core.FLOW_STATE

func ParseIP(s string) (IP4, bool) {
	return types.ParseIP(s)
}

func Console(addr string, logs *logger.Logger, passwd string) *stats.SServer {
	return stats.Server(addr, logs, passwd)
}

func LoadConfiguration(file string, ifname string, src types.IP4) (*config.Config, error) {
	return config.LoadConfiguration(file, ifname, src)
}

func Bootstrap(conf *config.Config, ctl *core.Control, l *logger.Logger, ws *stats.SServer) chan *config.Config {
	return manage.Bootstrap(conf, ctl, l, ws)
}

func New(veth string, vip IP4, hwaddr [6]byte, native, bridge bool, peth ...string) *core.Control {
	return core.New(core.BPF_O, veth, vip, hwaddr, native, bridge, peth[:]...)
}

func Daemon(path, ipaddr string) {
	probes.Daemon(path, ipaddr)
}

func Serve(netns string, logs *logger.Logger) {
	probes.Serve(netns, logs)
}

func NewLogger() *logger.Logger {
	return logger.NewLogger()
}

func LoadConf(file string) (*config2.Conf, error) {
	return config2.Load(file)
}

func NetnsServer(sock string) {
	netns.Server(sock, vc5bip.String())
}

func Load(conf *config2.Conf, mynet NET) (*healthchecks.Healthchecks, error) {
	return healthchecks.Load(mynet, conf)
}

type LoadBalancer = lb.LoadBalancer

/*
type LoadBalancer struct {
	KillSwitch      uint
	Native          bool
	Socket          string
	NetnsCommand    []string
	Interfaces      []string
	EgressInterface string
	Logger          types.Logger

	monitor  *monitor.Mon
	balancer *kernel.Balancer
	nat      *kernel.NAT
	maps     *kernel.Maps
	report   monitor.Report
	update   chan *healthchecks.Healthchecks
	mutex    sync.Mutex
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
	clean(VC5A, NAMESPACE)
}

func (lb *LoadBalancer) Update(hc *healthchecks.Healthchecks) {
	lb.update <- hc
}

func (lb *LoadBalancer) Start(ip IP4, hc *healthchecks.Healthchecks) error {

	l := lb.Logger

	if l == nil {
		l = &types.NilLogger{}
	}

	var cleanup bool = true

	defer func() {
		if cleanup {
			clean(VC5A, NAMESPACE)
		}
	}()

	bond := lb.EgressInterface
	peth := lb.Interfaces
	native := lb.Native
	args := lb.NetnsCommand
	sock := lb.Socket

	var vc5amac [6]byte
	var vc5bmac [6]byte

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

	setup1(VC5A, VC5B)

	iface, err := net.InterfaceByName(VC5A)
	if err != nil {
		return err
	}
	copy(vc5amac[:], iface.HardwareAddr[:])

	vc5aidx := iface.Index

	iface, err = net.InterfaceByName(VC5B)
	if err != nil {
		return err
	}
	copy(vc5bmac[:], iface.HardwareAddr[:])

	lb.maps, err = kernel.Open(native, VC5A, VC5B, peth...)

	if err != nil {
		return err
	}

	mode := uint8(kernel.MODE_SIMPLE)

	if hc.VLANMode {
		mode = kernel.MODE_VLAN
	}

	lb.maps.MODE(mode)

	cleanup = false

	setup2(NAMESPACE, VC5A, VC5B, vc5aip, vc5bip)

	go netns.Spawn(NAMESPACE, args...)

	lb.nat = lb.maps.NAT(hc, ip, bondidx, bondmac, vc5aidx, vc5aip, vc5bip, vc5amac, vc5bmac, l)
	lb.monitor, lb.report = monitor.Monitor(hc, vc5bip, sock, lb.nat.ARP(), l)
	lb.balancer = lb.maps.Balancer(lb.report, l)

	lb.update = make(chan *healthchecks.Healthchecks)
	go lb.background()

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

func (lb *LoadBalancer) background() {
	defer func() {
		lb.monitor.Close()
		lb.nat.Close()
		lb.balancer.Close()
	}()

	for {
		select {
		case h, ok := <-lb.update: // reconfigure NAT and healthchecks
			if !ok {
				return
			}
			lb.mutex.Lock()
			lb.nat.Configure(h)
			lb.monitor.Update(h)
			lb.mutex.Unlock()

		case report := <-lb.monitor.C: // new config to apply to load balancer
			lb.mutex.Lock()
			lb.report = report
			lb.balancer.Configure(report)
			lb.mutex.Unlock()
		}
	}
}

/**********************************************************************/
/*
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
