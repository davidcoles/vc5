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
type MAC = types.MAC
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

func Load(conf *config2.Conf) (*healthchecks.Healthchecks, error) {
	return healthchecks.Load(conf)
}

type LoadBalancer = lb.LoadBalancer
