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

func prometheus(p string, services map[netip.Addr][]Serv, summary Summary, vips map[netip.Addr]State) []string {
	r := []string{help(p)}

	var defcon uint8

	r = append(r, fmt.Sprintf(p+`_uptime %d`, summary.Uptime))
	r = append(r, fmt.Sprintf(p+`_defcon %d`, defcon))
	r = append(r, fmt.Sprintf(p+`_latency %d`, summary.Latency))
	r = append(r, fmt.Sprintf(p+`_sessions %d`, summary.Current))
	r = append(r, fmt.Sprintf(p+`_session_total %d`, summary.Flows))
	r = append(r, fmt.Sprintf(p+`_rx_packets %d`, summary.IngressPackets))
	r = append(r, fmt.Sprintf(p+`_rx_octets %d`, summary.IngressOctets))
	r = append(r, fmt.Sprintf(p+`_tx_packets %d`, summary.EgressPackets))
	r = append(r, fmt.Sprintf(p+`_tx_octets %d`, summary.EgressOctets))

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
		r = metric(r, p+`_vip_status{vip="%s"} %d`, vip, zeroone(s.up))
		r = metric(r, p+`_vip_status_duration{vip="%s",status="%s"} %d`, vip, updown(s.up), now.Sub(s.time)/time.Second)
	}

	for _, x := range services {
		for _, s := range x {
			//serv := fmt.Sprintf("%s:%d:%s", s.Address, s.Port, s.Protocol.string())
			serv := fmt.Sprintf("%s:%s:%d", s.Address, s.Protocol.string(), s.Port)
			name := s.Name
			stat := s.Stats
			up := zeroone(s.Up)

			name = strings.ReplaceAll(name, `\`, `\\`)
			name = strings.ReplaceAll(name, `"`, `\"`)

			r = metric(r, p+`_service_sessions{service="%s",name="%s"} %d`, serv, name, stat.Current)
			r = metric(r, p+`_service_sessions_total{service="%s",name="%s"} %d`, serv, name, stat.Flows)
			r = metric(r, p+`_service_rx_packets{service="%s",name="%s"} %d`, serv, name, stat.IngressPackets)
			r = metric(r, p+`_service_rx_octets{service="%s",name="%s"} %d`, serv, name, stat.IngressOctets)
			r = metric(r, p+`_service_tx_packets{service="%s",name="%s"} %d`, serv, name, stat.EgressPackets)
			r = metric(r, p+`_service_tx_octets{service="%s",name="%s"} %d`, serv, name, stat.EgressOctets)
			r = metric(r, p+`_service_status{service="%s",name="%s"} %d`, serv, name, up)
			r = metric(r, p+`_service_status_duration{service="%s",name="%s",status="%s"} %d`, serv, name, updown(s.Up), s.For)
			r = metric(r, p+`_service_reserves_used{service="%s",name="%s"} %d`, serv, name, 666)

			for _, d := range s.Destinations {
				real := fmt.Sprintf("%s:%d", d.Address, d.Port)
				up := zeroone(d.Up)

				r = metric(r, p+`_backend_sessions{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.Current)
				r = metric(r, p+`_backend_sessions_total{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.Flows)
				r = metric(r, p+`_backend_rx_packets{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.IngressPackets)
				r = metric(r, p+`_backend_rx_octets{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.IngressOctets)
				r = metric(r, p+`_backend_tx_packets{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.EgressPackets)
				r = metric(r, p+`_backend_tx_octets{service="%s",name="%s",backend="%s"} %d`, serv, name, real, stat.EgressOctets)
				r = metric(r, p+`_backend_status{service="%s",name="%s",backend="%s"} %d`, serv, name, real, up)
				r = metric(r, p+`_backend_status_duration{service="%s",name="%s",backend="%s",status="%s"} %d`, serv, name, real, updown(d.Up), d.For)
				r = metric(r, p+`_backend_reserves_used{service="%s",name="%s",backend="%s"} %d`, serv, name, real, 666)

			}
		}
	}

	//return strings.Join(r, "\n") + "\n"
	return r
}

func metric(l []string, f string, a ...any) []string {
	return append(l, fmt.Sprintf(f, a...))
}

func help(p string) string {
	return `# TYPE ` + p + `_uptime counter
# TYPE ` + p + `_defcon gauge
# TYPE ` + p + `_latency gauge
# TYPE ` + p + `_sessions gauge
# TYPE ` + p + `_session_total counter
# TYPE ` + p + `_rx_packets counter
# TYPE ` + p + `_rx_octets counter
# TYPE ` + p + `_tx_packets counter
# TYPE ` + p + `_tx_octets counter
# TYPE ` + p + `_vip_status gauge
# TYPE ` + p + `_vip_status_duration gauge
# TYPE ` + p + `_service_sessions gauge
# TYPE ` + p + `_service_sessions_total counter
# TYPE ` + p + `_service_rx_packets counter
# TYPE ` + p + `_service_rx_octets counter
# TYPE ` + p + `_service_tx_packets counter
# TYPE ` + p + `_service_tx_octets counter
# TYPE ` + p + `_service_status gauge
# TYPE ` + p + `_service_status_duration gauge
# TYPE ` + p + `_service_reserves_used gauge
# TYPE ` + p + `_backend_sessions gauge
# TYPE ` + p + `_backend_sessions_total counter
# TYPE ` + p + `_backend_rx_packets counter
# TYPE ` + p + `_backend_rx_octets counter
# TYPE ` + p + `_backend_tx_packets counter
# TYPE ` + p + `_backend_tx_octets counter
# TYPE ` + p + `_backend_status gauge
# TYPE ` + p + `_backend_status_duration gauge
# HELP ` + p + `_uptime Uptime in seconds
# HELP ` + p + `_defcon Readiness level
# HELP ` + p + `_latency Average packet processing latency in nanoseconds
# HELP ` + p + `_sessions Estimated number of current active sessions
# HELP ` + p + `_session_total Total number of new sessions written to state tracking table
# HELP ` + p + `_rx_packets Total number of incoming packets
# HELP ` + p + `_rx_octets Total number incoming bytes
# HELP ` + p + `_tx_packets Total number of outgoing packets
# HELP ` + p + `_tx_octets Total number outgoing bytes
# HELP ` + p + `_vip_status gauge
# HELP ` + p + `_vip_status_duration gauge
# HELP ` + p + `_service_sessions gauge
# HELP ` + p + `_service_sessions_total counter
# HELP ` + p + `_service_rx_packets counter
# HELP ` + p + `_service_rx_octets counter
# HELP ` + p + `_service_tx_packets counter
# HELP ` + p + `_service_tx_octets counter
# HELP ` + p + `_service_status gauge
# HELP ` + p + `_service_status_duration gauge
# HELP ` + p + `_service_reserves_used gauge
# HELP ` + p + `_backend_sessions gauge
# HELP ` + p + `_backend_sessions_total counter
# HELP ` + p + `_backend_rx_packets counter
# HELP ` + p + `_backend_rx_octets counter
# HELP ` + p + `_backend_tx_packets counter
# HELP ` + p + `_backend_tx_octets counter
# HELP ` + p + `_backend_status gauge
# HELP ` + p + `_backend_status_duration gauge`
}
