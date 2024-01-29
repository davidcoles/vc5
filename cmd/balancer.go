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

	"github.com/davidcoles/cue"
	"github.com/davidcoles/xvs"
)

type tuple struct {
	addr netip.Addr
	port uint16
	prot uint8
}

type Balancer struct {
	Client    *xvs.Client
	ProbeFunc func(vip, rip, nat netip.Addr, check cue.Check) (bool, string)
}

func (b *Balancer) Probe(vip netip.Addr, rip netip.Addr, check cue.Check) (bool, string) {

	f := b.ProbeFunc

	if f == nil {
		return false, "No probe function defined"
	}

	nat, ok := b.Client.NATAddress(vip, rip)

	if !ok {
		return false, "No NAT destination defined for " + vip.String() + "/" + rip.String()
	}

	return f(vip, rip, nat, check)
}

func (b *Balancer) Configure(services []cue.Service) error {

	target := map[tuple]cue.Service{}

	for _, s := range services {
		target[tuple{addr: s.Address, port: s.Port, prot: s.Protocol}] = s

		for _, d := range s.Destinations {
			if s.Port != d.Port {
				return errors.New("Destination ports must match service ports for DSR")
			}
		}
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {
		key := tuple{addr: s.Service.Address, port: s.Service.Port, prot: s.Service.Protocol}
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

		b.Client.SetService(service, dsts)
	}

	return nil
}
