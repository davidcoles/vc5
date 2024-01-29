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
	"fmt"
	"net/netip"
	"strings"
	"time"
)

func prometheus(services map[netip.Addr][]Serv, summary Summary, vips map[netip.Addr]State) []string {
	r := []string{help()}

	var defcon uint8

	r = append(r, fmt.Sprintf(`vc5_uptime %d`, summary.Uptime))
	r = append(r, fmt.Sprintf(`vc5_defcon %d`, defcon))
	r = append(r, fmt.Sprintf(`vc5_latency %d`, summary.Latency))
	r = append(r, fmt.Sprintf(`vc5_sessions %d`, summary.Current))
	r = append(r, fmt.Sprintf(`vc5_session_total %d`, summary.Flows))
	r = append(r, fmt.Sprintf(`vc5_rx_packets %d`, summary.Packets))
	r = append(r, fmt.Sprintf(`vc5_rx_octets %d`, summary.Octets))

	zeroone := func(u bool) uint8 {
		if u {
			return 1
		}
		return 0
	}

	updown := func(u bool) string {
		if u {
			return "up"
		}
		return "down"
	}

	now := time.Now()

	for vip, s := range vips {
		r = metric(r, `vc5_vip_status{vip="%s"} %d`, vip, zeroone(s.up))
		r = metric(r, `vc5_vip_status_duration{{vip="%s",status="%s"} %d`, vip, updown(s.up), now.Sub(s.time)/time.Second)
	}

	for _, x := range services {
		for _, s := range x {
			serv := fmt.Sprintf("%s:%d:%s", s.Address, s.Port, s.Protocol.string())
			name := s.Name
			stat := s.Stats
			up := zeroone(s.Up)

			name = strings.ReplaceAll(name, `\`, `\\`)
			name = strings.ReplaceAll(name, `"`, `\"`)

			r = metric(r, `vc5_service_sessions{service="%s",name="%s"} %d`, serv, name, stat.Current)
			r = metric(r, `vc5_service_sessions_total{service="%s",name="%s"} %d`, serv, name, stat.Flows)
			r = metric(r, `vc5_service_rx_packets{service="%s",name="%s"} %d`, serv, name, stat.Packets)
			r = metric(r, `vc5_service_rx_octets{service="%s",name="%s"} %d`, serv, name, stat.Octets)
			r = metric(r, `vc5_service_status{service="%s",name="%s"} %d`, serv, name, up)
			r = metric(r, `vc5_service_status_duration{service="%s",name="%s"} %d`, serv, name, s.For)
			r = metric(r, `vc5_service_reserves_used{service="%s",name="%s"} %d`, serv, name, 666)

			for _, d := range s.Destinations {
				real := fmt.Sprintf("%s:%d", d.Address, d.Port)
				up := zeroone(d.Up)

				r = metric(r, `vc5_backend_sessions{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.Current)
				r = metric(r, `vc5_backend_sessions_total{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.Flows)
				r = metric(r, `vc5_backend_rx_packets{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.Packets)
				r = metric(r, `vc5_backend_rx_octets{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.Octets)
				r = metric(r, `vc5_backend_status{service="%s",name="%s",backend="%s"} %d`, serv, name, real, up)
				r = metric(r, `vc5_backend_status_duration{service="%s",name="%s",backend="%s"} %d`, serv, name, real, d.For)
				r = metric(r, `vc5_backend_reserves_used{service="%s",name="%s",backend="%s"} %d`, serv, name, real, 666)

			}
		}
	}

	//return strings.Join(r, "\n") + "\n"
	return r
}

func metric(l []string, f string, a ...any) []string {
	return append(l, fmt.Sprintf(f, a...))
}

func help() string {
	return `# TYPE vc5_uptime counter
# TYPE vc5_defcon gauge
# TYPE vc5_latency gauge
# TYPE vc5_sessions gauge
# TYPE vc5_session_total counter
# TYPE vc5_rx_packets counter
# TYPE vc5_rx_octets counter
# TYPE vc5_vip_status gauge
# TYPE vc5_vip_status_duration gauge
# TYPE vc5_service_sessions gauge
# TYPE vc5_service_sessions_total counter
# TYPE vc5_service_rx_packets counter
# TYPE vc5_service_rx_octets counter
# TYPE vc5_service_status gauge
# TYPE vc5_service_status_duration gauge
# TYPE vc5_service_reserves_used gauge
# TYPE vc5_backend_sessions gauge
# TYPE vc5_backend_sessions_total counter
# TYPE vc5_backend_rx_packets counter
# TYPE vc5_backend_rx_octets counter
# TYPE vc5_backend_status gauge
# TYPE vc5_backend_status_duration gauge
# HELP vc5_uptime Uptime in seconds
# HELP vc5_defcon Readiness level
# HELP vc5_latency Average packet processing latency in nanoseconds
# HELP vc5_sessions Estimated number of current active sessions
# HELP vc5_session_total Total number of new sessions written to state tracking table
# HELP vc5_rx_packets Total number of incoming packets
# HELP vc5_rx_octets Total number incoming bytes
# HELP vc5_vip_status gauge
# HELP vc5_vip_status_duration gauge
# HELP vc5_service_sessions gauge
# HELP vc5_service_sessions_total counter
# HELP vc5_service_rx_packets counter
# HELP vc5_service_rx_octets counter
# HELP vc5_service_status gauge
# HELP vc5_service_status_duration gauge
# HELP vc5_service_reserves_used gauge
# HELP vc5_backend_sessions gauge
# HELP vc5_backend_sessions_total counter
# HELP vc5_backend_rx_packets counter
# HELP vc5_backend_rx_octets counter
# HELP vc5_backend_status gauge
# HELP vc5_backend_status_duration gauge`
}
