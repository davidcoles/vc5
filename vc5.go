package vc5

import (
	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/lb"
	"github.com/davidcoles/vc5/monitor/netns"
	"github.com/davidcoles/vc5/types"
)

var vc5bip IP4 = IP4{10, 255, 255, 254}

type IP4 = types.IP4
type MAC = types.MAC
type L4 = types.L4
type NET = types.NET
type Target = kernel.Target

func LoadConf(file string) (*config.Config, error) {
	return config.Load(file)
}

func NetnsServer(sock string) {
	netns.Server(sock, vc5bip.String())
}

func Load(conf *config.Config) (*healthchecks.Healthchecks, error) {
	return healthchecks.Load(conf)
}

type LoadBalancer = lb.LoadBalancer
