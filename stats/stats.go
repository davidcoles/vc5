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
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	//"github.com/davidcoles/vc5/core"
	"github.com/davidcoles/vc5/logger"
	"github.com/davidcoles/vc5/types"
)

//go:embed lb.html
var LB_HTML []byte

//go:embed lb.js
var LB_JS []byte

type scounters = types.Scounters
type counters = types.Counters

type global struct {
	Warning    string               `json:"warning"`
	Latency    uint64               `json:"average_latency_ns"`
	Pps        uint64               `json:"rx_packets_per_second"`
	Bps        uint64               `json:"rx_octets_per_second"`
	DEFCON     uint8                `json:"defcon"`
	Concurrent uint64               `json:"current_connections"`
	New_flows  uint64               `json:"total_connections"`
	Rx_packets uint64               `json:"rx_packets"`
	Rx_octets  uint64               `json:"rx_octets"`
	Qfailed    uint64               `json:"userland_queue_failed"`
	RHI        map[string]bool      `json:"route_health_injection"`
	Services   map[string]scounters `json:"services"`
}

//func (ctrl *Control) stats_server() {

type SServer struct {
	vips       chan map[string]bool
	scountersc chan scounters
	countersc  chan counters
	DEFCON     chan uint8
	username   string
	password   string
}

func Server(addr string, logs *logger.Logger, password string) *SServer {
	ss := &SServer{
		scountersc: make(chan scounters, 100),
		countersc:  make(chan counters, 100),
		DEFCON:     make(chan uint8, 1),
		vips:       make(chan map[string]bool, 100),
		username:   "defcon",
		password:   password,
	}
	go ss.Server_(addr, logs)
	return ss
}

func (s *SServer) VIPs() chan map[string]bool { return s.vips }
func (s *SServer) Counters() chan counters    { return s.countersc }
func (s *SServer) Scounters() chan scounters  { return s.scountersc }

func (ss *SServer) Server_(addr string, logs *logger.Logger) {

	var js []byte = []byte("{}")

	var metrics []byte

	go func() {

		var g global
		g.Warning = "JSON structure subject to change at any time - very much in development!"
		g.RHI = make(map[string]bool)
		g.Services = make(map[string]scounters)

		//var vips map[string]bool

		var cooked counters

		for {
			select {
			case v := <-ss.vips:
				g.RHI = v

			case c := <-ss.scountersc:

				//key := fmt.Sprint(c.VIP, c.Port, c.UDP)
				svc := c.Service()
				key := svc.String()

				if c.Delete {
					//delete(g.Services, c.Sname)
					delete(g.Services, key)
				} else {
					//g.Services[c.Sname] = c
					g.Services[key] = c
				}

			case c := <-ss.countersc:
				cooked = c
			}

			g.Latency = cooked.Latency
			g.Pps = cooked.Rx_pps
			g.Bps = cooked.Rx_bps
			g.DEFCON = cooked.DEFCON
			g.New_flows = cooked.New_flows
			g.Rx_packets = cooked.Rx_packets
			g.Rx_octets = cooked.Rx_octets
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
		w.Write(LB_HTML)
		//w.Write(index())
	})

	http.HandleFunc("/lb.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write(LB_HTML)
	})
	http.HandleFunc("/lb.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		w.Write(LB_JS)
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

	http.HandleFunc("/defcon/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		user := ss.username
		pass := ss.password
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

		auth, ok := r.Header["Authorization"]

		if pass == "" || !ok || len(auth) < 1 || auth[0] != basic {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if len(r.RequestURI) != 9 {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var d uint8
		switch r.RequestURI[8] {
		case '1':
			d = 1
		case '2':
			d = 2
		case '3':
			d = 3
		case '4':
			d = 4
		case '5':
			d = 5
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)

		select {
		case ss.DEFCON <- d:
			w.Write([]byte(fmt.Sprintln("DEFCON:", d)))
		default:
		}
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		history := logs.Dump()

		re := regexp.MustCompile("^/log/([0-9]+)$")
		match := re.FindStringSubmatch(r.RequestURI)

		if match != nil && len(match) == 2 {
			n, _ := strconv.ParseUint(match[1], 10, 64)
			history = logs.Since(uint64(n))
		}

		if j, err := json.MarshalIndent(history, "", "  "); err != nil {
			log.Println(err)
			w.Write([]byte(`[]`))
		} else {
			w.Write(j)
		}
		w.Write([]byte("\n"))

	})

	http.HandleFunc("/log/text/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		var level uint8 = logger.LOG_NOTICE
		if len(r.RequestURI) == 11 {
			switch r.RequestURI[10] {
			case '0':
				level = 0
			case '1':
				level = 1
			case '2':
				level = 2
			case '3':
				level = 3
			case '4':
				level = 4
			case '5':
				level = 5
			case '6':
				level = 6
			case '7':
				level = 7
			}
		}

		txt := logs.Text(level)

		x := 100
		if len(txt) > x {
			n := len(txt)
			txt = txt[n-x:]
		}

		for _, t := range txt {
			w.Write([]byte(t))
		}
	})

	log.Fatal(http.ListenAndServe(addr, nil))
}

func index() []byte {
	s := `<html>
  <head>
    <title>VC5</title>
  </head>
  <body>
    <h1>VC5</h1>
    <li><a href="/stats/">stats</a></li>
    <li><a href="/log/text/5">logs</a></li>
    <li><a href="/log/text/7">debug logs</a></li>
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
		"# TYPE vc5_defcon gauge",

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
	m = append(m, fmt.Sprintf("vc5_rx_octets %d", g.Rx_octets))
	m = append(m, fmt.Sprintf("vc5_userland_queue_failed %d", g.Qfailed))
	m = append(m, fmt.Sprintf("vc5_defcon %d", g.DEFCON))

	for i, v := range g.RHI {
		m = append(m, fmt.Sprintf(`vc5_rhi{address="%s"} %d`, i, b2u8(v)))
	}

	for s, v := range g.Services {
		//d := v.Description
		n := v.Name
		m = append(m, fmt.Sprintf(`vc5_service_current_connections{service="%s",sname="%s"} %d`, s, n, v.Concurrent))
		m = append(m, fmt.Sprintf(`vc5_service_total_connections{service="%s",sname="%s"} %d`, s, n, v.New_flows))
		m = append(m, fmt.Sprintf(`vc5_service_rx_packets{service="%s",sname="%s"} %d`, s, n, v.Rx_packets))
		m = append(m, fmt.Sprintf(`vc5_service_rx_octets{service="%s",sname="%s"} %d`, s, n, v.Rx_octets))

		m = append(m, fmt.Sprintf(`vc5_service_healthcheck{service="%s",sname="%s"} %d`, s, n, b2u8(v.Up)))

		for b, v := range v.Backends {
			m = append(m, fmt.Sprintf(`vc5_backend_current_connections{service="%s",backend="%s"} %d`, s, b, v.Concurrent))
			m = append(m, fmt.Sprintf(`vc5_backend_total_connections{service="%s",backend="%s"} %d`, s, b, v.New_flows))
			m = append(m, fmt.Sprintf(`vc5_backend_rx_packets{service="%s",backend="%s"} %d`, s, b, v.Rx_packets))
			m = append(m, fmt.Sprintf(`vc5_backend_rx_octets{service="%s",backend="%s"} %d`, s, b, v.Rx_octets))

			m = append(m, fmt.Sprintf(`vc5_backend_healthcheck{service="%s",backend="%s"} %d`, s, b, b2u8(v.Up)))
		}
	}

	all := strings.Join(m, "\n")
	return []byte(all)
}
