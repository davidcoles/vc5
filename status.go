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

package vc5

import (
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/bgp"
)

type Services map[VIP][]serv

//type Serv = serv
type serv struct {
	Name         string     `json:"name,omitempty"`
	Description  string     `json:"description"`
	Address      netip.Addr `json:"address"`
	Port         uint16     `json:"port"`
	Protocol     protocol   `json:"protocol"`
	Required     uint8      `json:"required"`
	Available    uint8      `json:"available"`
	Stats        Stats      `json:"stats"`
	Destinations []dest     `json:"destinations,omitempty"`
	Up           bool       `json:"up"`
	For          uint64     `json:"for"`
	Last         uint64     `json:"last"`
	Sticky       bool       `json:"sticky"`
	Scheduler    string     `json:"scheduler"`
}

//type Dest = dest
type dest struct {
	Address    netip.Addr `json:"address"`
	Port       uint16     `json:"port"`
	Stats      Stats      `json:"stats"`
	Weight     uint8      `json:"weight"`
	Disabled   bool       `json:"disabled"`
	Up         bool       `json:"up"`
	For        uint64     `json:"for"`
	Took       uint64     `json:"took"`
	When       uint64     `json:"when"`
	Last       uint64     `json:"last"`
	Diagnostic string     `json:"diagnostic"`
	MAC        string     `json:"mac"`
}

type State struct {
	up   bool
	time time.Time
}

func (s *State) Up() bool        { return s.up }
func (s *State) Time() time.Time { return s.time }

type Stats struct {
	IngressOctets  uint64 `json:"ingress_octets"`
	IngressPackets uint64 `json:"ingress_packets"`
	EgressOctets   uint64 `json:"egress_octets"`
	EgressPackets  uint64 `json:"egress_packets"`
	Flows          uint64 `json:"flows"`
	Current        uint64 `json:"current"`

	IngressOctetsPerSecond  uint64 `json:"ingress_octets_per_second"`
	IngressPacketsPerSecond uint64 `json:"ingress_packets_per_second"`
	EgressOctetsPerSecond   uint64 `json:"egress_octets_per_second"`
	EgressPacketsPerSecond  uint64 `json:"egress_packets_per_second"`
	FlowsPerSecond          uint64 `json:"flows_per_second"`
	time                    time.Time
	MAC                     string `json:"mac,omitempty"`
}

type Summary struct {
	Uptime             uint64 `json:"uptime"`
	Latency            uint64 `json:"latency_ns"`
	Dropped            uint64 `json:"dropped"`
	Blocked            uint64 `json:"blocked"`
	NotQueued          uint64 `json:"notqueued"`
	DroppedPerSecond   uint64 `json:"dropped_per_second"`
	BlockedPerSecond   uint64 `json:"blocked_per_second"`
	NotQueuedPerSecond uint64 `json:"notqueued_per_second"`

	IngressOctets           uint64 `json:"ingress_octets"`
	IngressPackets          uint64 `json:"ingress_packets"`
	Flows                   uint64 `json:"flows"`
	Current                 uint64 `json:"current"`
	IngressOctetsPerSecond  uint64 `json:"ingress_octets_per_second"`
	IngressPacketsPerSecond uint64 `json:"ingress_packets_per_second"`
	FlowsPerSecond          uint64 `json:"flows_per_second"`
	EgressOctets            uint64 `json:"egress_octets"`
	EgressPackets           uint64 `json:"egress_packets"`
	EgressOctetsPerSecond   uint64 `json:"egress_octets_per_second"`
	EgressPacketsPerSecond  uint64 `json:"egress_packets_per_second"`
	DSR                     bool   `json:"dsr"`
	VC5                     bool   `json:"vc5"`

	time time.Time
}

func (s *Stats) add(x Stats) {
	s.IngressOctets += x.IngressOctets
	s.IngressPackets += x.IngressPackets
	s.Flows += x.Flows
	s.Current += x.Current
	s.IngressOctetsPerSecond += x.IngressOctetsPerSecond
	s.IngressPacketsPerSecond += x.IngressPacketsPerSecond
	s.FlowsPerSecond += x.FlowsPerSecond

	s.EgressOctets += x.EgressOctets
	s.EgressPackets += x.EgressPackets
	s.EgressOctetsPerSecond += x.EgressOctetsPerSecond
	s.EgressPacketsPerSecond += x.EgressPacketsPerSecond

}

type VIP = netip.Addr
type VIPStats struct {
	VIP   VIP    `json:"vip"`
	Up    bool   `json:"up"`
	Stats Stats  `json:"stats"`
	For   uint64 `json:"for"`
}

//func VipStatus(in map[VIP][]Serv, foo map[netip.Addr]State) (out []VIPStats) {
func VipStatus(in Services, foo map[netip.Addr]State) (out []VIPStats) {

	for vip, list := range in {
		var stats Stats
		for _, s := range list {
			stats.add(s.Stats)
		}

		r, ok := foo[vip]
		if !ok {
			r.time = time.Now()
		}

		out = append(out, VIPStats{VIP: vip, Stats: stats, Up: r.up, For: uint64(time.Now().Sub(r.time) / time.Second)})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].VIP.Compare(out[j].VIP) < 0
	})

	return
}

func VipState(services []cue.Service, old map[netip.Addr]State, priorities map[netip.Addr]priority, logs Logger) map[netip.Addr]State {
	facility := "vips"

	rib := map[netip.Addr]bool{}
	new := map[netip.Addr]State{}

	for _, v := range cue.HealthyVIPs(services) {
		rib[v] = true
	}

	for _, v := range cue.AllVIPs(services) {
		p, _ := priorities[v]
		log := logs.ERR

		switch p {
		case CRITICAL:
			log = logs.ERR
		case HIGH:
			log = logs.WARNING
		case MEDIUM:
			log = logs.NOTICE
		case LOW:
			log = logs.INFO
		}

		updown := func(b bool) string {
			if b {
				return "up"
			}
			return "down"
		}

		if o, ok := old[v]; ok {
			up, _ := rib[v]

			if o.up != up {
				new[v] = State{up: up, time: time.Now()}
				log(facility, KV{"vip": v, "state": updown(up), "event": "vip"})
			} else {
				new[v] = o
			}

		} else {
			log(facility, KV{"vip": v, "state": updown(rib[v]), "event": "vip"})
			new[v] = State{up: rib[v], time: time.Now()}
		}
	}

	return new
}

func AdjRIBOut(vip map[netip.Addr]State, initialised bool) (r []netip.Addr) {
	for v, s := range vip {
		if initialised && s.up && time.Now().Sub(s.time) > time.Second*5 {
			r = append(r, v)
		}
	}
	return
}

func (s *Summary) Update(n Summary, start time.Time) {

	o := *s
	*s = n

	s.Uptime = uint64(time.Now().Sub(start) / time.Second)
	s.time = time.Now()

	if o.time.Unix() != 0 {
		diff := uint64(s.time.Sub(o.time) / time.Millisecond)

		if diff != 0 {
			s.DroppedPerSecond = (1000 * (s.Dropped - o.Dropped)) / diff
			s.BlockedPerSecond = (1000 * (s.Blocked - o.Blocked)) / diff
			s.NotQueuedPerSecond = (1000 * (s.NotQueued - o.NotQueued)) / diff

			s.IngressPacketsPerSecond = (1000 * (s.IngressPackets - o.IngressPackets)) / diff
			s.IngressOctetsPerSecond = (1000 * (s.IngressOctets - o.IngressOctets)) / diff
			s.EgressPacketsPerSecond = (1000 * (s.EgressPackets - o.EgressPackets)) / diff
			s.EgressOctetsPerSecond = (1000 * (s.EgressOctets - o.EgressOctets)) / diff
			s.FlowsPerSecond = (1000 * (s.Flows - o.Flows)) / diff
		}
	}
}

type Service struct {
	Address  netip.Addr
	Port     uint16
	Protocol Protocol
}

type Destination struct {
	Address netip.Addr
	Port    uint16
}

type Instance struct {
	Service     Service
	Destination Destination
}

type Balancer interface {
	TCPStats() map[Instance]TCPStats
	Destinations(s Service) (map[Destination]Stats, error)
}

func calculateRate(s Stats, o Stats) Stats {

	s.time = time.Now()

	if o.time.Unix() != 0 {
		diff := uint64(s.time.Sub(o.time) / time.Millisecond)

		if diff != 0 {
			s.EgressPacketsPerSecond = (1000 * (s.EgressPackets - o.EgressPackets)) / diff
			s.EgressOctetsPerSecond = (1000 * (s.EgressOctets - o.EgressOctets)) / diff
			s.IngressPacketsPerSecond = (1000 * (s.IngressPackets - o.IngressPackets)) / diff
			s.IngressOctetsPerSecond = (1000 * (s.IngressOctets - o.IngressOctets)) / diff
			s.FlowsPerSecond = (1000 * (s.Flows - o.Flows)) / diff
		}
	}

	return s
}

type TCPStats struct {
	SYN_RECV    uint64
	ESTABLISHED uint64
	CLOSE       uint64
	TIME_WAIT   uint64
}

//func ServiceStatus(config *Config, balancer Balancer, director *cue.Director, old map[Instance]Stats) (map[netip.Addr][]Serv, map[Instance]Stats, uint64) {
func ServiceStatus(config *Config, balancer Balancer, director *cue.Director, old map[Instance]Stats) (Services, map[Instance]Stats, uint64) {

	var current uint64

	stats := map[Instance]Stats{}
	status := Services{} //map[netip.Addr][]Serv{}
	tcpstats := balancer.TCPStats()

	for _, svc := range director.Status() {

		cnf, _ := config.Services[service(svc)]
		key := serviceInstance(svc)
		lbs, _ := balancer.Destinations(service(svc))

		var sum Stats
		for _, s := range lbs {
			sum.add(s)
		}

		serv := serv{
			Name:        cnf.Name,
			Description: cnf.Description,
			Address:     svc.Address,
			Port:        svc.Port,
			Protocol:    protocol(svc.Protocol),
			Required:    svc.Required,
			Available:   svc.Available(),
			Up:          svc.Up,
			For:         uint64(time.Now().Sub(svc.When) / time.Second),
			Sticky:      svc.Sticky,
			Scheduler:   svc.Scheduler,
			Stats:       calculateRate(sum, old[key]),
		}

		for _, dst := range svc.Destinations {
			key := destinationInstance(svc, dst)
			dest := dest{
				Address:    dst.Address,
				Port:       dst.Port,
				Disabled:   dst.Disabled,
				Up:         dst.Status.OK,
				For:        uint64(time.Now().Sub(dst.Status.When) / time.Second),
				Took:       uint64(dst.Status.Took / time.Millisecond),
				Diagnostic: dst.Status.Diagnostic,
				Weight:     dst.Weight,
				Stats:      calculateRate(lbs[destination(dst)], old[key]),
				MAC:        lbs[destination(dst)].MAC,
			}

			if tcp, ok := tcpstats[destinationInstance(svc, dst)]; ok {
				dest.Stats.Current = tcp.ESTABLISHED
				serv.Stats.Current += tcp.ESTABLISHED
				current += tcp.ESTABLISHED
			}

			stats[key] = dest.Stats
			serv.Destinations = append(serv.Destinations, dest)
		}

		stats[key] = serv.Stats

		sort.SliceStable(serv.Destinations, func(i, j int) bool {
			return serv.Destinations[i].Address.Compare(serv.Destinations[j].Address) < 0
		})

		status[svc.Address] = append(status[svc.Address], serv)
	}

	return status, stats, current
}

func service(s cue.Service) Service {
	return Service{Address: s.Address, Port: s.Port, Protocol: Protocol(s.Protocol)}
}

func destination(dst cue.Destination) Destination {
	return Destination{Address: dst.Address, Port: dst.Port}
}

func destinationInstance(s cue.Service, d cue.Destination) Instance {
	return Instance{
		Service:     Service{Address: s.Address, Port: s.Port, Protocol: Protocol(s.Protocol)},
		Destination: Destination{Address: d.Address, Port: d.Port},
	}
}
func serviceInstance(s cue.Service) Instance {
	return Instance{Service: Service{Address: s.Address, Port: s.Port, Protocol: Protocol(s.Protocol)}}
}

func JSONStatus(summary Summary, services Services, vips map[netip.Addr]State, pool *bgp.Pool, rib []netip.Addr, logstats LogStats) ([]byte, error) {
	return json.MarshalIndent(struct {
		Summary  Summary               `json:"summary"`
		Services Services              `json:"services"`
		BGP      map[string]bgp.Status `json:"bgp"`
		VIP      []VIPStats            `json:"vip"`
		RIB      []netip.Addr          `json:"rib"`
		Logging  LogStats              `json:"logging"`
	}{
		Summary:  summary,
		Services: services,
		BGP:      pool.Status(),
		VIP:      VipStatus(services, vips),
		RIB:      rib,
		Logging:  logstats,
	}, " ", " ")
}
