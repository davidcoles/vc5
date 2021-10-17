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
	"encoding/json"
	"log"
	"net/http"
)

type global struct {
	Warning    string               `json:"warning"`
	Latency    uint64               `json:"average_latency_ns"`
	Pps        uint64               `json:"packets_per_second"`
	New_flows  uint64               `json:"total_connections"`
	Rx_packets uint64               `json:"rx_packets"`
	Rx_bytes   uint64               `json:"rx_octets"`
	Qfailed    uint64               `json:"userland_queue_failed"`
	RHI        map[string]bool      `json:"route_health_injection"`
	Services   map[string]scounters `json:"services"`
}

func (ctrl *Control) stats_server() {

	var js []byte = []byte("{}")

	go func() {

		var g global
		g.Warning = "JSON structure subject to change at any time - very much in development!"
		g.RHI = make(map[string]bool)
		g.Services = make(map[string]scounters)

		for {
			select {
			case r := <-ctrl.rhi:
				g.RHI[r.ip.String()] = r.up

			case c := <-ctrl.scounters:
				g.Services[c.name] = c
			}

			g.Latency = ctrl.latency
			g.Pps = ctrl.pps
			g.New_flows = ctrl.raw.New_flows
			g.Rx_packets = ctrl.raw.Rx_packets
			g.Rx_bytes = ctrl.raw.Rx_bytes
			g.Qfailed = ctrl.raw.qfailed

			j, err := json.MarshalIndent(&g, "", "  ")

			if err == nil {
				js = j
			}
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write(index())
	})

	http.HandleFunc("/stats/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if j, err := json.MarshalIndent(ctrl.logger.Dump(), "", "  "); err != nil {
			w.Write([]byte("{}"))
		} else {
			w.Write(j)
		}
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/log/text", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		for _, t := range ctrl.logger.Text() {
			w.Write([]byte(t))
		}
	})

	log.Fatal(http.ListenAndServe(":80", nil))
}

func index() []byte {
	s := `<html>
  <head>
    <title>VC5</title>
  </head>
  <body>
    <h1>VC5</h1>
    <li><a href="/stats/">stats</a></li>
    <li><a href="/log/text">logs</a></li>    
  </body>
</html>
`

	return []byte(s)
}
