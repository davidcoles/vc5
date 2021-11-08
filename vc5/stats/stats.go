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

package stats

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"vc5/types"
)

type scounters = types.Scounters
type counters = types.Counters

type global struct {
	Warning    string               `json:"warning"`
	Latency    uint64               `json:"average_latency_ns"`
	Pps        uint64               `json:"packets_per_second"`
	Concurrent uint64               `json:"current_connections"`
	New_flows  uint64               `json:"total_connections"`
	Rx_packets uint64               `json:"rx_packets"`
	Rx_bytes   uint64               `json:"rx_octets"`
	Qfailed    uint64               `json:"userland_queue_failed"`
	RHI        map[string]bool      `json:"route_health_injection"`
	Services   map[string]scounters `json:"services"`
}

//func (ctrl *Control) stats_server() {
func Stats_server(rhic chan types.RHI, scountersc chan scounters, cooked *counters, latency *uint64, pps *uint64) {

	var js []byte = []byte("{}")

	var metrics []byte

	go func() {

		var g global
		g.Warning = "JSON structure subject to change at any time - very much in development!"
		g.RHI = make(map[string]bool)
		g.Services = make(map[string]scounters)

		for {
			select {
			case r := <-rhic:
				g.RHI[r.Ip.String()] = r.Up

			case c := <-scountersc:
				g.Services[c.Sname] = c
			}

			g.Latency = *latency
			g.Pps = *pps
			g.New_flows = cooked.New_flows
			g.Rx_packets = cooked.Rx_packets
			g.Rx_bytes = cooked.Rx_bytes
			g.Qfailed = cooked.Qfailed

			g.Concurrent = 0
			for _, s := range g.Services {
				g.Concurrent += uint64(s.Concurrent)
			}

			j, err := json.MarshalIndent(&g, "", "  ")

			if err == nil {
				js = j
			}

			metrics = prometheus(&g)
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write(index())
	})

	http.HandleFunc("/stats/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write(metrics)
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		/*
			if j, err := json.MarshalIndent(ctrl.logger.Dump(), "", "  "); err != nil {
				w.Write([]byte("{}"))
			} else {
				w.Write(j)
			}
			w.Write([]byte("\n"))
		*/
	})

	http.HandleFunc("/log/text", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		/*
			for _, t := range ctrl.logger.Text() {
				w.Write([]byte(t))
			}
		*/
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

func prometheus(g *global) []byte {

	m := []string{
		"# TYPE vc5_average_latency_ns gauge",
		"# TYPE vc5_packets_per_second gauge",
		"# TYPE vc5_current_connections gauge",
		"# TYPE vc5_total_connections counter",
		"# TYPE vc5_rx_packets counter",
		"# TYPE vc5_rx_octets counter",
		"# TYPE vc5_userland_queue_failed counter",

		"# TYPE vc5_rhi gauge",

		"# TYPE vc5_service_current_connections gauge",
		"# TYPE vc5_service_total_connections counter",
		"# TYPE vc5_service_rx_packets counter",
		"# TYPE vc5_service_rx_octets counter",
		"# TYPE vc5_service_healthcheck gauge",

		"# TYPE vc5_backend_current_connections gauge",
		"# TYPE vc5_backend_total_connections counter",
		"# TYPE vc5_backend_rx_packets counter",
		"# TYPE vc5_backend_rx_octets counter",
		"# TYPE vc5_backend_healthcheck gauge",
	}

	b2u8 := func(v bool) uint8 {
		if v {
			return 1
		}
		return 0
	}

	m = append(m, fmt.Sprintf("vc5_average_latency_ns %d", g.Latency))
	m = append(m, fmt.Sprintf("vc5_packets_per_second %d", g.Pps))
	m = append(m, fmt.Sprintf(`vc5_current_connections %d`, g.Concurrent))
	m = append(m, fmt.Sprintf("vc5_total_connections %d", g.New_flows))
	m = append(m, fmt.Sprintf("vc5_rx_packets %d", g.Rx_packets))
	m = append(m, fmt.Sprintf("vc5_rx_octets %d", g.Rx_bytes))
	m = append(m, fmt.Sprintf("vc5_userland_queue_failed %d", g.Qfailed))

	for i, v := range g.RHI {
		m = append(m, fmt.Sprintf(`vc5_rhi{address="%s"} %d`, i, b2u8(v)))
	}

	for s, v := range g.Services {
		//d := v.Description
		n := v.Name
		m = append(m, fmt.Sprintf(`vc5_service_current_connections{service="%s",sname="%s"} %d`, s, n, v.Concurrent))
		m = append(m, fmt.Sprintf(`vc5_service_total_connections{service="%s",sname="%s"} %d`, s, n, v.New_flows))
		m = append(m, fmt.Sprintf(`vc5_service_rx_packets{service="%s",sname="%s"} %d`, s, n, v.Rx_packets))
		m = append(m, fmt.Sprintf(`vc5_service_rx_octets{service="%s",sname="%s"} %d`, s, n, v.Rx_bytes))

		m = append(m, fmt.Sprintf(`vc5_service_healthcheck{service="%s",sname="%s"} %d`, s, n, b2u8(v.Up)))

		for b, v := range v.Backends {
			m = append(m, fmt.Sprintf(`vc5_backend_current_connections{service="%s",backend="%s"} %d`, s, b, v.Concurrent))
			m = append(m, fmt.Sprintf(`vc5_backend_total_connections{service="%s",backend="%s"} %d`, s, b, v.New_flows))
			m = append(m, fmt.Sprintf(`vc5_backend_rx_packets{service="%s",backend="%s"} %d`, s, b, v.Rx_packets))
			m = append(m, fmt.Sprintf(`vc5_backend_rx_octets{service="%s",backend="%s"} %d`, s, b, v.Rx_bytes))

			m = append(m, fmt.Sprintf(`vc5_backend_healthcheck{service="%s",backend="%s"} %d`, s, b, b2u8(v.Up)))
		}
	}

	all := strings.Join(m, "\n")
	return []byte(all)
}