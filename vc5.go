package vc5

import (
	//"errors"
	//"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

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
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/netns"
)

type Control = core.Control
type IP4 = types.IP4
type L4 = types.L4
type Target = kernel.Target
type Status = monitor.Report

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

/**********************************************************************/

type VC5 struct {
	hc       chan *healthchecks.Healthchecks
	monitor  *monitor.Mon
	nat      chan *healthchecks.Healthchecks
	balancer chan monitor.Report
	stats    func() map[kernel.Target]kernel.Counter
	maps     *kernel.Maps
	notify   func(IP4, bool)
	report   monitor.Report
	mutex    sync.Mutex
}

func NetnsServer(sock string) {
	netns.Server(sock)
}

func LoadConf(file string) (*config2.Conf, error) {
	return config2.Load(file, nil)
}

func Controller(native bool, ip IP4, hc *healthchecks.Healthchecks, args []string, sock, bond string, peth ...string) (*VC5, error) {

	var cleanup bool = true

	ns := "vc5"
	vc5a := "vc5a"
	vc5b := "vc5b"

	defer func() {
		if cleanup {
			clean(vc5a, "vc5")
		}
	}()

	eth := []string{vc5a, vc5b}
	eth = append(eth, peth...)

	var vc5amac [6]byte
	var vc5bmac [6]byte

	var bondidx int

	if bond != "" {
		iface, err := net.InterfaceByName(bond)
		if err != nil {
			return nil, err
		}
		bondidx = iface.Index
	} else {
		iface, err := net.InterfaceByName(peth[0])
		if err != nil {
			return nil, err
		}
		bondidx = iface.Index
	}

	setup1(vc5a, vc5b)

	iface, err := net.InterfaceByName(vc5a)
	if err != nil {
		return nil, err
	}
	copy(vc5amac[:], iface.HardwareAddr[:])

	vc5aidx := iface.Index

	iface, err = net.InterfaceByName(vc5b)
	if err != nil {
		return nil, err
	}
	copy(vc5bmac[:], iface.HardwareAddr[:])

	maps := kernel.Open(bond, native, eth...)

	fmt.Println(maps)

	cleanup = false

	var vc5aip [4]byte = [4]byte{10, 255, 255, 253}
	var vc5bip [4]byte = [4]byte{10, 255, 255, 254}

	setup2(ns, vc5a, vc5b, vc5aip, vc5bip)

	go netns.Spawn(ns, args...)

	nat, lookup := maps.NAT(ip, hc, bondidx, vc5aidx, vc5aip, vc5bip, vc5amac, vc5bmac)
	mon := monitor.Monitor(hc, vc5bip, sock, lookup)
	report := mon.Report()
	balancer, stats := maps.Balancer(report)

	vc5 := &VC5{hc: make(chan *healthchecks.Healthchecks), monitor: mon, nat: nat, balancer: balancer, stats: stats, maps: maps, report: report}

	go vc5.background()

	return vc5, nil
}

func (v *VC5) GlobalStats() (uint64, uint64, uint64, uint8) {
	return v.maps.GlobalStats()
}

func (v *VC5) Status() monitor.Report {
	v.mutex.Lock()
	r := v.report
	v.mutex.Unlock()
	return r
}

func (v *VC5) Stats() map[kernel.Target]kernel.Counter {
	return v.stats()
}

func (v *VC5) DEFCON(d uint8) uint8 {
	return v.maps.DEFCON(d)
}

func (v *VC5) Close() {
	close(v.hc)
	clean("vc5a", "vc5")
}

func (v *VC5) Update(hc *healthchecks.Healthchecks) {
	v.hc <- hc
}

func (v *VC5) background() {
	defer func() {
		v.monitor.Close()
		close(v.nat)
		close(v.balancer)
	}()

	for {
		select {
		case h, ok := <-v.hc:
			if !ok {
				return
			}
			v.mutex.Lock()
			v.nat <- h
			v.monitor.Update(h)
			v.mutex.Unlock()

		case <-time.After(5 * time.Second):
			v.mutex.Lock()
			v.report = v.monitor.Report()
			v.balancer <- v.report
			v.mutex.Unlock()
		}
	}
}

/**********************************************************************/

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
