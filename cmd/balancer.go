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
	"net"

	"github.com/davidcoles/xvs"
	"vc5"
)

// Implement the vc5.Balancer interface; used to retrieve stats and configure the data-plane

type Balancer struct {
	Client Client
	Logger vc5.Logger
	tunnel xvs.TunnelType
}

// func (b *Balancer) Stats() map[vc5.Instance]vc5.Stats {
func (b *Balancer) Stats() (summary vc5.Summary, stats map[vc5.Instance]vc5.Stats) {

	info, _ := b.Client.Info()
	summary.Latency = info.Latency
	//summary.Dropped = info.Dropped
	//summary.Blocked = info.Blocked
	//summary.TooBig = info.TooBig
	//summary.NotQueued = info.NotQueued
	summary.IngressOctets = info.Stats.Octets
	summary.IngressPackets = info.Stats.Packets
	//summary.EgressOctets = 0  // Not available in DSR
	//summary.EgressPackets = 0 // Not available in DSR
	summary.Flows = info.Stats.Flows
	summary.Current = info.Stats.Current
	summary.DSR = true
	summary.VC5 = true

	stats = map[vc5.Instance]vc5.Stats{}
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
				MAC:            net.HardwareAddr(d.MAC[:]).String(),
			}
		}
	}

	return
}

// Synchronise the manifest of services from the director/manager to the xvs client
func (b *Balancer) Configure(manifests []vc5.Manifest) error {

	from_xvs := func(s Service) vc5.Service {
		return vc5.Service{Address: s.Address, Port: s.Port, Protocol: vc5.Protocol(s.Protocol)}
	}

	services := map[vc5.Service]vc5.Manifest{}

	// create a map of desired services and check that DSR restrictions are followed:
	for _, s := range manifests {
		services[s.Service()] = s

		for _, d := range s.Destinations {
			if s.Port != d.Port {
				return errors.New("Destination ports must match service ports for DSR")
			}
		}
	}

	// iterate through a list of active services and remove if no longer needed (desn't exist in the 'services' map):
	svcs, _ := b.Client.Services()
	for _, s := range svcs {
		if _, wanted := services[from_xvs(s.Service)]; !wanted {
			b.Client.RemoveService(s.Service)
		}
	}

	// for each desired service create the necessary xvs configuration (service description and list of backends) and apply:
	for _, s := range services {
		//service := Service{Address: s.Address, Port: s.Port, Protocol: Protocol(s.Protocol), Sticky: s.Sticky}
		service := Service{Address: s.Address, Port: s.Port, Protocol: Protocol(s.Protocol)}

		if s.Sticky {
			service.Flags |= xvs.Sticky
		}

		var dsts []Destination

		for _, d := range s.Destinations {
			if d.Port == s.Port {
				dsts = append(dsts, Destination{
					Address:    d.Address,
					Disable:    d.HealthyWeight() == 0,
					TunnelType: b.tunnel,
					TunnelPort: 666,
				})
			}
		}

		b.Client.SetService(service, dsts...)
	}

	return nil
}

// func (b *Balancer) metrics() (_names, values []string) {
func (b *Balancer) Metrics() (n []string, metrics []string) {

	client := b.Client

	names := map[string]bool{}

	info, _ := client.Info()
	//fmt.Println("Info", info)

	//w.Write([]byte(fmt.Sprintf("# TYPE xvs_global_latency gauge\n")))
	names["global_latency"] = true
	metrics = append(metrics, fmt.Sprintf("global_latency %d", info.Latency))

	for k, v := range info.Metrics {
		name := "global_" + k
		inst := ""
		line := fmt.Sprintf("%s%s %d", name, inst, v)
		names[name] = true
		metrics = append(metrics, line)
	}

	services, _ := client.Services()

	for _, service := range services {

		s, _ := client.Service(service.Service)

		serv := s.Service
		proto := ""
		switch serv.Protocol {
		case xvs.TCP:
			proto = "tcp"
		case xvs.UDP:
			proto = "udp"
		default:
			proto = fmt.Sprint(proto)
		}
		snam := fmt.Sprintf("%s:%d:%s", serv.Address, serv.Port, proto)

		for k, v := range s.Metrics {
			inst := fmt.Sprintf(`{address="%s",port="%d",protocol="%s",service="%s"}`, serv.Address, serv.Port, proto, snam)
			name := "service_" + k
			line := fmt.Sprintf("%s%s %d", name, inst, v)
			names[name] = true
			metrics = append(metrics, line)
		}

		destinations, _ := client.Destinations(serv)

		for _, d := range destinations {
			dest := d.Destination

			for k, v := range d.Metrics {
				inst := fmt.Sprintf(`{address="%s",port="%d",protocol="%s",destination="%s",service="%s"}`, serv.Address, serv.Port, proto, dest.Address, snam)
				name := "destination_" + k
				line := fmt.Sprintf("%s%s %d", name, inst, v)
				names[name] = true
				metrics = append(metrics, line)
			}
		}
	}

	vips, _ := client.VIPs()

	for _, vip := range vips {
		for k, v := range vip.Metrics {
			inst := fmt.Sprintf(`{address="%s"}`, vip.Address)
			name := "virtual_" + k
			line := fmt.Sprintf("%s%s %d", name, inst, v)
			names[name] = true
			metrics = append(metrics, line)
		}
	}

	for k, _ := range names {
		n = append(n, k)
	}

	return
}
