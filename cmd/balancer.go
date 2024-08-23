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
	"net/netip"

	"github.com/davidcoles/xvs"

	"vc5"
)

const TCP = vc5.TCP
const UDP = vc5.UDP

type Client = *xvs.Client
type Balancer struct {
	NetNS  *nns
	Logger *vc5.Sub
	Client *xvs.Client
}

func (b *Balancer) Destinations(s vc5.Service) (map[vc5.Destination]vc5.Stats, error) {
	stats := map[vc5.Destination]vc5.Stats{}
	ds, err := b.Client.Destinations(xvs.Service{Address: s.Address, Port: s.Port, Protocol: uint8(s.Protocol)})
	for _, d := range ds {
		key := vc5.Destination{Address: d.Destination.Address, Port: s.Port}
		stats[key] = vc5.Stats{
			IngressOctets:  d.Stats.Octets,
			IngressPackets: d.Stats.Packets,
			EgressOctets:   0, // Not available in DSR
			EgressPackets:  0, // Not available in DSR
			Flows:          d.Stats.Flows,
			MAC:            d.MAC.String(),
		}
	}
	return stats, err
}

func (b *Balancer) TCPStats() map[vc5.Instance]vc5.TCPStats {
	tcp := map[vc5.Instance]vc5.TCPStats{}
	svcs, _ := b.Client.Services()
	for _, se := range svcs {
		s := se.Service
		dsts, _ := b.Client.Destinations(s)
		for _, de := range dsts {
			d := de.Destination
			i := vc5.Instance{
				Service:     vc5.Service{Address: s.Address, Port: s.Port, Protocol: vc5.Protocol(s.Protocol)},
				Destination: vc5.Destination{Address: d.Address, Port: s.Port},
			}
			tcp[i] = vc5.TCPStats{ESTABLISHED: de.Stats.Current}
		}
	}

	return tcp
}

//func (b *Balancer) Configure(services []cue.Service) error {
func (b *Balancer) Configure(services []vc5.CService) error {

	type tuple struct {
		Address  netip.Addr
		Port     uint16
		Protocol uint8
	}

	target := map[tuple]vc5.CService{}

	for _, s := range services {
		target[tuple{Address: s.Address, Port: s.Port, Protocol: s.Protocol}] = s

		for _, d := range s.Destinations {
			if s.Port != d.Port {
				return errors.New("Destination ports must match service ports for DSR")
			}
		}
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {
		key := tuple{Address: s.Service.Address, Port: s.Service.Port, Protocol: s.Service.Protocol}
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

/*
// interface method called by mon when a destination needs to be probed - find the NAT address and probe that via the netns
func (b *Balancer) Probe(_ *mon.Mon, instance mon.Instance, check mon.Check) (ok bool, diagnostic string) {

	vip := instance.Service.Address
	rip := instance.Destination.Address
	nat, ok := b.Client.NATAddress(vip, rip)

	if !ok {
		diagnostic = "No NAT destination defined for " + vip.String() + "/" + rip.String()
	} else {
		ok, diagnostic = b.NetNS.Probe(nat, check)
	}

	return ok, diagnostic
}
*/
