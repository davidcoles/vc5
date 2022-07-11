package vc5

import (
	//"errors"
	//"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/core"
	"github.com/davidcoles/vc5/logger"
	"github.com/davidcoles/vc5/manage"
	"github.com/davidcoles/vc5/probes"
	"github.com/davidcoles/vc5/stats"
	"github.com/davidcoles/vc5/types"
	//"github.com/davidcoles/vc5/xdp"

	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	namespace "github.com/davidcoles/vc5/netns"
)

type Control = core.Control
type IP4 = types.IP4
type L4 = types.L4
type Target = kernel.Target

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
	ns chan *healthchecks.Healthchecks
	fn func(*healthchecks.Healthchecks, bool) monitor.Report
	hc chan *healthchecks.Healthchecks
	lb chan monitor.Report
	ss func() map[kernel.Target]kernel.Counter
}

func Server(sock string) {
	namespace.Server(sock)
}

func (v *VC5) HC(hc *healthchecks.Healthchecks) {
}

func Controller(ip IP4, hc *healthchecks.Healthchecks, sock, bond string, peth ...string) (*VC5, error) {

	var cleanup bool = true

	netns := "vc5"
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

	iface, err := net.InterfaceByName(bond)
	if err != nil {
		return nil, err
	}
	bondidx := iface.Index

	setup1(vc5a, vc5b)

	iface, err = net.InterfaceByName(vc5a)
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

	m := kernel.Open(eth...)

	fmt.Println(m)

	cleanup = false

	var vc5aip [4]byte = [4]byte{10, 255, 255, 253}
	var vc5bip [4]byte = [4]byte{10, 255, 255, 254}

	setup2(netns, vc5a, vc5b, vc5aip, vc5bip)

	go namespace.Go(netns, os.Args[0], "-s", sock)

	done := make(chan bool)
	ns, lu := m.NAT(ip, hc, done, bondidx, vc5aidx, vc5aip, vc5bip, vc5amac, vc5bmac)
	fn := monitor.Monitor(hc, vc5bip, sock, lu)

	cf := fn(nil, false)
	lb, stats := kernel.Lbengine(m, cf, done)

	vc5 := &VC5{ns: ns, fn: fn, hc: make(chan *healthchecks.Healthchecks), lb: lb, ss: stats}

	go vc5.background(hc)

	return vc5, nil
}

func (v *VC5) Config() monitor.Report {
	return v.fn(nil, false)
}

func (v *VC5) Stats() map[kernel.Target]kernel.Counter {
	return v.ss()
}

func (v *VC5) Close() {
	//close(v.hc)
	clean("vc5a", "vc5")
}

func (v *VC5) Update(hc *healthchecks.Healthchecks) {
	v.hc <- hc
}

func (v *VC5) background(hc *healthchecks.Healthchecks) {
	defer func() {
		v.fn(nil, true)
		close(v.ns)
		close(v.lb)
	}()

	for {
		select {
		case h, ok := <-v.hc:
			if !ok {
				return
			}
			hc = h
			v.ns <- hc
			v.fn(hc, false)

		case <-time.After(5 * time.Second):
			v.lb <- v.fn(nil, false)
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
