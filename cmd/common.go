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
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/davidcoles/cue"
)

type Serv struct {
	Name         string     `json:"name,omitempty"`
	Description  string     `json:"description"`
	Address      netip.Addr `json:"address"`
	Port         uint16     `json:"port"`
	Protocol     protocol   `json:"protocol"`
	Required     uint8      `json:"required"`
	Available    uint8      `json:"available"`
	Stats        Stats      `json:"stats"`
	Destinations []Dest     `json:"destinations,omitempty"`
	Up           bool       `json:"up"`
	For          uint64     `json:"for"`
	Last         uint64     `json:"last"`
}

type Dest struct {
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

type Key struct {
	VIP      netip.Addr
	RIP      netip.Addr
	Port     uint16
	RPort    uint16
	Protocol uint8
}

type State struct {
	up   bool
	time time.Time
}

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
	VIP   VIP   `json:"vip"`
	Up    bool  `json:"up"`
	Stats Stats `json:"stats"`
}

func vipStatus(in map[VIP][]Serv, rib []netip.Addr) (out []VIPStats) {

	up := map[VIP]bool{}

	for _, r := range rib {
		up[r] = true
	}

	for vip, list := range in {
		var stats Stats
		for _, s := range list {
			stats.add(s.Stats)
		}

		out = append(out, VIPStats{VIP: vip, Stats: stats, Up: up[vip]})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].VIP.Compare(out[j].VIP) < 0
	})

	return
}

func vipState(services []cue.Service, old map[netip.Addr]State, logs *logger) map[netip.Addr]State {
	F := "vips"

	rib := map[netip.Addr]bool{}
	new := map[netip.Addr]State{}

	for _, v := range cue.HealthyVIPs(services) {
		rib[v] = true
	}

	for _, v := range cue.AllVIPs(services) {

		if o, ok := old[v]; ok {
			up, _ := rib[v]

			if o.up != up {
				new[v] = State{up: up, time: time.Now()}
				logs.NOTICE(F, KV{"vip": v, "state": updown(up), "event": "vip"})
			} else {
				new[v] = o
			}

		} else {
			logs.NOTICE(F, KV{"vip": v, "state": updown(rib[v]), "event": "vip"})
			new[v] = State{up: rib[v], time: time.Now()}
		}
	}

	return new
}

func adjRIBOut(vip map[netip.Addr]State, initialised bool) (r []netip.Addr) {
	for v, s := range vip {
		if initialised && s.up && time.Now().Sub(s.time) > time.Second*5 {
			r = append(r, v)
		}
	}
	return
}

func updown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

func (s *Summary) update(c Client, t uint64) Summary {
	o := *s

	s.summary(c)

	s.Uptime = t
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

	return *s
}

func bgpListener(l net.Listener, logs Logger) {
	F := "listener"

	for {
		conn, err := l.Accept()

		if err != nil {
			logs.ERR(F, "Failed to accept connection", err)
		} else {
			go func(c net.Conn) {
				logs.INFO(F, "Accepted connection from", conn.RemoteAddr())
				defer c.Close()
				time.Sleep(time.Minute)
			}(conn)
		}
	}
}
