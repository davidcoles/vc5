package vc5

import (
	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/core"
	"github.com/davidcoles/vc5/logger"
	"github.com/davidcoles/vc5/manage"
	"github.com/davidcoles/vc5/probes"
	"github.com/davidcoles/vc5/stats"
	"github.com/davidcoles/vc5/types"
	//"github.com/davidcoles/vc5/xdp"
)

type Control = core.Control
type IP4 = types.IP4

const FLOW_STATE = core.FLOW_STATE

func Console(addr string, logs *logger.Logger) *stats.SServer {
	return stats.Server(addr, logs)
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
