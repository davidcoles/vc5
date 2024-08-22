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
	"fmt"
	"net/netip"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/mon"
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

func (b *Balancer) configure(services []cue.Service) error {

	type tuple struct {
		Address  netip.Addr
		Port     uint16
		Protocol uint8
	}

	target := map[tuple]cue.Service{}

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

func (b *Balancer) summary() (s vc5.Summary) {
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

// event.module:
// - health-check: state-change state check
// - vip-status
// - service-status
//

func _cs(s mon.Service) vc5.Service {
	return vc5.Service{Address: s.Address, Port: s.Port, Protocol: vc5.Protocol(s.Protocol)}
}

func _cd(d mon.Destination) vc5.Destination {
	return vc5.Destination{Address: d.Address, Port: d.Port}
}

type _s bool

func (s _s) String() string {
	if s {
		return "up"
	}
	return "down"
}

// interface method called by mon when a destination's health status transitions up or down
func (b *Balancer) Notify(instance mon.Instance, state bool) {
	if logger := b.Logger; logger != nil {
		//logger.NOTICE("notify", notifyLog(instance, state))
		//logger.Event(5, "healthcheck", "state-change", notifyLog(instance, state))
		text := fmt.Sprintf("Backend %s for service %s went %s", _cd(instance.Destination), _cs(instance.Service), _s(state))
		logger.Alert(5, "healthcheck", "state", notifyLog(instance, state), text)
	}
}

// interface method called by mon every time a round of checks for a service on a destination is completed
func (b *Balancer) Result(instance mon.Instance, state bool, diagnostic string) {
	if logger := b.Logger; logger != nil {
		//logger.DEBUG("result", resultLog(instance, state, diagnostic))
		logger.Event(7, "healthcheck", "state", resultLog(instance, state, diagnostic))
	}
}

func (b *Balancer) Check(instance mon.Instance, check string, round uint64, state bool, diagnostic string) {
	nat, _ := b.Client.NATAddress(instance.Service.Address, instance.Destination.Address)

	// check.type
	// check.status
	// check.port
	// check.url

	if logger := b.Logger; logger != nil {
		//logger.DEBUG("check", checkLog(instance, state, diagnostic, check, round, nat))
		logger.Event(7, "healthcheck", "check", checkLog(instance, state, diagnostic, check, round, nat))
	}
}

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

	//if b.Logger != nil {
	//	b.Logger.DEBUG("probe", probeLog(instance, nat, fmt.Sprint(check), ok, diagnostic))
	//}

	return ok, diagnostic
}

func updown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

func notifyLog(instance mon.Instance, state bool) map[string]any {

	proto := func(p uint8) string {
		switch instance.Service.Protocol {
		case TCP:
			return "tcp"
		case UDP:
			return "udp"
		}
		return fmt.Sprintf("%d", p)
	}

	// https://www.elastic.co/guide/en/ecs/current/ecs-base.html
	// https://github.com/elastic/ecs/blob/main/generated/csv/fields.csv
	return map[string]any{
		//"state": updown(state),
		//"proto": proto(instance.Service.Protocol),
		//"saddr": instance.Service.Address.String(),
		//"sport": instance.Service.Port,
		//"daddr": instance.Destination.Address.String(),
		//"dport": instance.Destination.Port,

		"service.state":    updown(state),
		"service.protocol": proto(instance.Service.Protocol),
		"service.ip":       instance.Service.Address.String(),
		"service.port":     instance.Service.Port,
		"destination.ip":   instance.Destination.Address.String(),
		"destination.port": instance.Destination.Port,
	}
}

func resultLog(instance mon.Instance, status bool, diagnostic string) map[string]any {
	r := notifyLog(instance, status)
	r["diagnostic"] = diagnostic
	return r
}

//func probeLog(instance mon.Instance, addr netip.Addr, check string, status bool, diagnostic string) map[string]any {
//	r := resultLog(instance, status, diagnostic)
//	r["check"] = check
//	//r["paddr"] = addr
//	r["destination.nat.ip"] = addr
//	return r
//}

func checkLog(instance mon.Instance, status bool, diagnostic string, check string, round uint64, nat netip.Addr) map[string]any {
	r := resultLog(instance, status, diagnostic)
	r["check"] = check
	r["round"] = round
	r["destination.nat.ip"] = nat
	return r
}
