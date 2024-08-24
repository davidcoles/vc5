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

package main

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"

	"github.com/davidcoles/xvs"

	"vc5"
)

type Client = *xvs.Client
type Balancer struct {
	//NetNS  *nns
	NetNS  *http.Client
	Logger vc5.Logger
	Client Client
}

func (b *Balancer) Stats() map[vc5.Instance]vc5.Stats {
	stats := map[vc5.Instance]vc5.Stats{}

	services, _ := b.Client.Services()

	for _, s := range services {
		protocol := vc5.Protocol(s.Service.Protocol)
		service := vc5.Service{Address: s.Service.Address, Port: s.Service.Port, Protocol: protocol}

		destinations, _ := b.Client.Destinations(s.Service)

		for _, d := range destinations {

			destination := vc5.Destination{Address: d.Destination.Address, Port: s.Service.Port}

			instance := vc5.Instance{
				Service:     service,
				Destination: destination,
			}

			stats[instance] = vc5.Stats{
				IngressOctets:  d.Stats.Octets,
				IngressPackets: d.Stats.Packets,
				EgressOctets:   0, // Not available in DSR
				EgressPackets:  0, // Not available in DSR
				Flows:          d.Stats.Flows,
				Current:        d.Stats.Current,
				MAC:            d.MAC.String(),
			}
		}
	}

	return stats
}

func (b *Balancer) Configure(services []vc5.ServiceManifest) error {

	foo := func(s xvs.Service) vc5.Service {
		return vc5.Service{Address: s.Address, Port: s.Port, Protocol: vc5.Protocol(s.Protocol)}
	}

	bar := func(s vc5.ServiceManifest) vc5.Service {
		return vc5.Service{Address: s.Address, Port: s.Port, Protocol: vc5.Protocol(s.Protocol)}
	}

	target := map[vc5.Service]vc5.ServiceManifest{}

	for _, s := range services {
		target[bar(s)] = s

		for _, d := range s.Destinations {
			if s.Port != d.Port {
				return errors.New("Destination ports must match service ports for DSR")
			}
		}
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {
		key := foo(s.Service)
		if _, wanted := target[key]; !wanted {
			b.Client.RemoveService(s.Service)
		}
	}

	for _, s := range target {
		service := xvs.Service{Address: s.Address, Port: s.Port, Protocol: xvs.Protocol(s.Protocol), Sticky: s.Sticky}

		var dsts []xvs.Destination

		for _, d := range s.Destinations {
			if d.Port == s.Port {
				dsts = append(dsts, xvs.Destination{
					Address: d.Address,
					Weight:  d.HealthyWeight(),
				})
			}
		}

		b.Client.SetService(service, dsts...)
	}

	return nil
}

func (b *Balancer) Summary() (s vc5.Summary) {
	u := b.Client.Info()
	s.Latency = u.Latency
	s.Dropped = u.Dropped
	s.Blocked = u.Blocked
	s.NotQueued = u.NotQueued
	s.IngressOctets = u.Octets
	s.IngressPackets = u.Packets
	s.EgressOctets = 0  // Not available in DSR
	s.EgressPackets = 0 // Not available in DSR
	s.Flows = u.Flows

	s.DSR = true
	s.VC5 = true

	return
}

func (b *Balancer) nat() func(vip, rip netip.Addr) netip.Addr {
	return func(vip, rip netip.Addr) netip.Addr {
		nat, _ := b.Client.NATAddress(vip, rip)
		return nat
	}
}

func (b *Balancer) prober() func(i vc5.Instance, check vc5.Check) (ok bool, diagnostic string) {
	return func(i vc5.Instance, check vc5.Check) (ok bool, diagnostic string) {
		vip := i.Service.Address
		rip := i.Destination.Address
		nat, ok := b.Client.NATAddress(vip, rip)

		if check.Host == "" {
			check.Host = rip.String() // URL would consist of NAT address if no host field set, which could be confusing
		}

		if !ok {
			diagnostic = "No NAT destination defined for " + vip.String() + "/" + rip.String()
		} else {
			ok, diagnostic = probe(b.NetNS, nat, check)
		}

		return ok, diagnostic
	}
}

func (b *Balancer) start(socket *os.File, cmd_sock net.Listener, mcast string) {
	go readCommands(cmd_sock, b.Client, b.Logger)
	go spawn(b.Logger, b.Client.Namespace(), os.Args[0], "-s", socket.Name(), b.Client.NamespaceAddress())
	if mcast != "" {
		multicast(b.Client, mcast)
	}
}
