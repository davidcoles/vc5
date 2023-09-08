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
	"log"
	"strings"
	"sync"
	"time"
)

func getStats(lb *LoadBalancer) *Stats {

	now := time.Now()
	status := lb.Status()
	global, counters := lb.Stats()
	stats := Stats{
		Octets:  global.Octets,
		Packets: global.Packets,
		Flows:   global.Flows,
		Latency: global.Latency,
		DEFCON:  global.DEFCON,
		Blocked: global.Blocked,
		VIPs:    map[IP4]map[L4]Service{},
		RHI:     map[string]bool{},
		When:    map[IP4]int64{},
	}

	for k, v := range status.Health() {
		stats.RHI[k.String()] = v.Up
		stats.When[k] = int64(now.Sub(v.Time) / time.Second)
	}

	for svc, s := range status.Services() {
		vip := svc.VIP
		l4 := svc.L4()

		if _, ok := stats.VIPs[vip]; !ok {
			stats.VIPs[vip] = map[L4]Service{}
		}

		//reals := map[IP4]Real{}
		reals := map[string]Real{}

		var servers uint8
		var healthy uint8

		//for rip, real := range s.Reals_() {
		for _, real := range s.Reals() {
			rip := real.RIP
			servers++

			probe := real.Probe()

			if probe.Passed {
				healthy++
			}

			t := Target{VIP: vip, RIP: rip, Protocol: l4.Protocol.Number(), Port: l4.Port}
			c := counters[t]

			stats.Concurrent += c.Concurrent

			ipport := real.IPPort()

			//reals[rip.String()] = Real{
			reals[ipport.String()] = Real{
				Up:         probe.Passed,
				When:       int64(time.Now().Sub(probe.Time) / time.Second),
				Message:    probe.Message,
				Duration:   int64(probe.Duration / time.Millisecond),
				Octets:     c.Octets,
				Packets:    c.Packets,
				Flows:      c.Flows,
				Concurrent: c.Concurrent,
				MAC:        real.MAC.String(),
			}
		}

		stats.VIPs[vip][l4] = Service{
			Reals:       reals,
			Up:          s.Healthy,
			When:        int64(now.Sub(s.Change) / time.Second),
			Fallback:    s.Fallback,
			FallbackOn:  s.FallbackOn,
			FallbackUp:  s.FallbackProbe.Passed,
			Name:        s.Metadata.Name,
			Description: s.Metadata.Description,
			Servers:     servers,
			Healthy:     healthy,
			Minimum:     uint8(s.Minimum),
		}
	}

	return &stats
}

/**********************************************************************/
// Render stats structures into Prometheus metrics
/**********************************************************************/

func prometheus(g *Stats, start time.Time) []byte {

	uptime := time.Now().Sub(start) / time.Second

	//# HELP haproxy_backend_status Current status of the service (frontend: 0=STOP, 1=UP, 2=FULL - backend: 0=DOWN, 1=UP - server: 0=DOWN, 1=UP, 2=MAINT, 3=DRAIN, 4=NOLB).

	m := []string{

		// TYPE

		`# TYPE vc5_uptime counter`,
		"# TYPE vc5_defcon gauge",
		"# TYPE vc5_latency gauge",
		`# TYPE vc5_sessions gauge`,
		"# TYPE vc5_session_total counter",
		"# TYPE vc5_rx_packets counter",
		"# TYPE vc5_rx_octets counter",

		`# TYPE vc5_vip_status gauge`,
		`# TYPE vc5_vip_status_duration gauge`,

		`# TYPE vc5_service_sessions gauge`,
		`# TYPE vc5_service_sessions_total counter`,
		`# TYPE vc5_service_rx_packets counter`,
		`# TYPE vc5_service_rx_octets counter`,
		`# TYPE vc5_service_status gauge`,
		`# TYPE vc5_service_status_duration gauge`,
		`# TYPE vc5_service_reserves_used gauge`,

		`# TYPE vc5_backend_sessions gauge`,
		`# TYPE vc5_backend_sessions_total counter`,
		`# TYPE vc5_backend_rx_packets counter`,
		`# TYPE vc5_backend_rx_octets counter`,
		`# TYPE vc5_backend_status gauge`,
		`# TYPE vc5_backend_status_duration gauge`,

		// HELP

		`# HELP vc5_uptime Uptime in seconds`,
		"# HELP vc5_defcon Readiness level",
		"# HELP vc5_latency Average packet processing latency in nanoseconds",
		`# HELP vc5_sessions Estimated number of current active sessions`,
		"# HELP vc5_session_total Total number of new sessions written to state tracking table",
		"# HELP vc5_rx_packets Total number of incoming packets",
		"# HELP vc5_rx_octets Total number incoming bytes",

		`# HELP vc5_vip_status gauge`,
		`# HELP vc5_vip_status_duration gauge`,

		`# HELP vc5_service_sessions gauge`,
		`# HELP vc5_service_sessions_total counter`,
		`# HELP vc5_service_rx_packets counter`,
		`# HELP vc5_service_rx_octets counter`,
		`# HELP vc5_service_status gauge`,
		`# HELP vc5_service_status_duration gauge`,
		`# HELP vc5_service_reserves_used gauge`,

		`# HELP vc5_backend_sessions gauge`,
		`# HELP vc5_backend_sessions_total counter`,
		`# HELP vc5_backend_rx_packets counter`,
		`# HELP vc5_backend_rx_octets counter`,
		`# HELP vc5_backend_status gauge`,
		`# HELP vc5_backend_status_duration gauge`,
	}

	b2u8 := func(v bool) uint8 {
		if v {
			return 1
		}
		return 0
	}

	updown := func(v bool) string {
		if v {
			return "up"
		}
		return "down"
	}

	m = append(m, fmt.Sprintf(`vc5_uptime %d`, uptime))
	m = append(m, fmt.Sprintf("vc5_defcon %d", g.DEFCON))
	m = append(m, fmt.Sprintf("vc5_latency %d", g.Latency))
	m = append(m, fmt.Sprintf(`vc5_sessions %d`, g.Concurrent))
	m = append(m, fmt.Sprintf("vc5_session_total %d", g.Flows))
	m = append(m, fmt.Sprintf("vc5_rx_packets %d", g.Packets))
	m = append(m, fmt.Sprintf("vc5_rx_octets %d", g.Octets))

	for i, v := range g.When {
		m = append(m, fmt.Sprintf(`vc5_vip_status{vip="%s"} %d`, i, b2u8(g.RHI[i.String()])))
		m = append(m, fmt.Sprintf(`vc5_vip_status_duration{vip="%s",status="%s"} %d`, i, updown(g.RHI[i.String()]), v))
	}

	for vip, services := range g.VIPs {

		for l4, v := range services {
			labels := fmt.Sprintf(`service="%s"`, vip.String()+":"+l4.String())

			if !*nolabel && v.Name != "" {
				labels += fmt.Sprintf(`,name="%s"`, v.Name)
			}

			reserve := int(v.Servers) - int(v.Minimum) // eg. 3 reserve servers
			reserve_used := int(v.Servers) - int(v.Healthy)

			var reserve_used_percent = reserve_used * 100

			if reserve > 0 {
				reserve_used_percent = (100 * int(reserve_used)) / int(reserve)
			}

			m = append(m, fmt.Sprintf(`vc5_service_sessions{%s} %d`, labels, v.Concurrent))
			m = append(m, fmt.Sprintf(`vc5_service_sessions_total{%s} %d`, labels, v.Flows))
			m = append(m, fmt.Sprintf(`vc5_service_rx_packets{%s} %d`, labels, v.Packets))
			m = append(m, fmt.Sprintf(`vc5_service_rx_octets{%s} %d`, labels, v.Octets))
			m = append(m, fmt.Sprintf(`vc5_service_status{%s} %d`, labels, b2u8(v.Up)))
			m = append(m, fmt.Sprintf(`vc5_service_status_duration{%s,status="%s"} %d`, labels, updown(v.Up), v.When))
			m = append(m, fmt.Sprintf(`vc5_service_reserve_used{%s} %d`, labels, reserve_used_percent))

			for b, v := range v.Reals {
				l := labels + fmt.Sprintf(`,backend="%s"`, b)
				m = append(m, fmt.Sprintf(`vc5_backend_sessions{%s} %d`, l, v.Concurrent))
				m = append(m, fmt.Sprintf(`vc5_backend_sessions_total{%s} %d`, l, v.Flows))
				m = append(m, fmt.Sprintf(`vc5_backend_rx_packets{%s} %d`, l, v.Packets))
				m = append(m, fmt.Sprintf(`vc5_backend_rx_octets{%s} %d`, l, v.Octets))
				m = append(m, fmt.Sprintf(`vc5_backend_status{%s} %d`, l, b2u8(v.Up)))
				m = append(m, fmt.Sprintf(`vc5_backend_status_duration{%s,status="%s"} %d`, l, updown(v.Up), v.When))
			}
		}
	}

	return []byte(strings.Join(m, "\n") + "\n")
}

/**********************************************************************/
// Simple logging setup
/**********************************************************************/

type line struct {
	Time     time.Time
	Ms       int64
	Level    uint8
	Facility string
	Entry    []interface{}
	Text     string
}

type Logger struct {
	mu      sync.Mutex
	history []line
	Level   uint8
}

func (l *Logger) Log(level uint8, facility string, entry ...interface{}) {
	var a []interface{}
	a = append(a, level)
	a = append(a, facility)
	a = append(a, entry...)

	if level <= l.Level {
		log.Println(a...)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	ms := int64(time.Now().UnixNano() / int64(time.Millisecond))
	text := fmt.Sprintln(a...)

	if level < LOG_DEBUG {
		l.history = append(l.history, line{Ms: ms, Time: time.Now(), Level: level, Facility: facility, Entry: entry, Text: text})
	}

	for len(l.history) > 10000 {
		l.history = l.history[1:]
	}
}

func (l *Logger) Dump() []line {
	l.mu.Lock()
	defer l.mu.Unlock()
	hl := len(l.history)
	h := make([]line, hl)

	for n, v := range l.history {
		h[(hl-1)-n] = v
	}

	return h
}

func (l *Logger) Since(t int64) []line {
	for i, v := range l.Dump() {
		if v.Ms > t {
			return l.history[i:]
		}
	}
	return []line{}
}

func (l *Logger) EMERG(f string, e ...interface{})   { l.Log(LOG_EMERG, f, e...) }
func (l *Logger) ALERT(f string, e ...interface{})   { l.Log(LOG_ALERT, f, e...) }
func (l *Logger) CRIT(f string, e ...interface{})    { l.Log(LOG_CRIT, f, e...) }
func (l *Logger) ERR(f string, e ...interface{})     { l.Log(LOG_ERR, f, e...) }
func (l *Logger) WARNING(f string, e ...interface{}) { l.Log(LOG_WARNING, f, e...) }
func (l *Logger) NOTICE(f string, e ...interface{})  { l.Log(LOG_NOTICE, f, e...) }
func (l *Logger) INFO(f string, e ...interface{})    { l.Log(LOG_INFO, f, e...) }
func (l *Logger) DEBUG(f string, e ...interface{})   { l.Log(LOG_DEBUG, f, e...) }

const (
	LOG_EMERG   = 0 /* system is unusable */
	LOG_ALERT   = 1 /* action must be taken immediately */
	LOG_CRIT    = 2 /* critical conditions */
	LOG_ERR     = 3 /* error conditions */
	LOG_WARNING = 4 /* warning conditions */
	LOG_NOTICE  = 5 /* normal but significant condition */
	LOG_INFO    = 6 /* informational */
	LOG_DEBUG   = 7 /* debug-level messages */
)

/**********************************************************************/
// JSON schema for web interface updates
/**********************************************************************/

type Stats struct {
	Octets     uint64                 `json:"octets"`
	OctetsPS   uint64                 `json:"octets_ps"`
	Packets    uint64                 `json:"packets"`
	PacketsPS  uint64                 `json:"packets_ps"`
	Flows      uint64                 `json:"flows"`
	FlowsPS    uint64                 `json:"flows_ps"`
	Blocked    uint64                 `json:"blocked"`
	BlockedPS  uint64                 `json:"blocked_ps"`
	Concurrent uint64                 `json:"concurrent"`
	Latency    uint64                 `json:"latency"`
	DEFCON     uint8                  `json:"defcon"`
	RHI        map[string]bool        `json:"rhi"`
	When       map[IP4]int64          `json:"when"`
	VIPs       map[IP4]map[L4]Service `json:"vips"`
}

type Service struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Up          bool            `json:"up"`
	When        int64           `json:"when"`
	Fallback    bool            `json:"fallback"`
	FallbackOn  bool            `json:"fallback_on"`
	FallbackUp  bool            `json:"fallback_up"`
	Octets      uint64          `json:"octets"`
	OctetsPS    uint64          `json:"octets_ps"`
	Packets     uint64          `json:"packets"`
	PacketsPS   uint64          `json:"packets_ps"`
	Flows       uint64          `json:"flows"`
	FlowsPS     uint64          `json:"flows_ps"`
	Concurrent  uint64          `json:"concurrent"`
	Reals       map[string]Real `json:"rips"`
	Minimum     uint8           `json:"minimum"`
	Servers     uint8           `json:"servers"`
	Healthy     uint8           `json:"healthy"`
}

type Real struct {
	Up         bool   `json:"up"`
	When       int64  `json:"when"`
	Message    string `json:"message"`
	Duration   int64  `json:"duration_ms"`
	Octets     uint64 `json:"octets"`
	OctetsPS   uint64 `json:"octets_ps"`
	Packets    uint64 `json:"packets"`
	PacketsPS  uint64 `json:"packets_ps"`
	Flows      uint64 `json:"flows"`
	FlowsPS    uint64 `json:"flows_ps"`
	Concurrent uint64 `json:"concurrent"`
	MAC        string `json:"mac"`
}

func (s *Service) Total() {
	for _, v := range s.Reals {
		s.Octets += v.Octets
		s.OctetsPS += v.OctetsPS
		s.Packets += v.Packets
		s.PacketsPS += v.PacketsPS
		s.Flows += v.Flows
		s.FlowsPS += v.FlowsPS
		s.Concurrent += v.Concurrent
	}
}

func (r Real) Sub(o Real, dur time.Duration) Real {
	r.OctetsPS = (uint64(time.Second) * (r.Octets - o.Octets)) / uint64(dur)
	r.PacketsPS = (uint64(time.Second) * (r.Packets - o.Packets)) / uint64(dur)
	r.FlowsPS = (uint64(time.Second) * (r.Flows - o.Flows)) / uint64(dur)
	return r
}

func (n *Stats) Sub(o *Stats, dur time.Duration) *Stats {

	if o != nil {

		n.OctetsPS = (uint64(time.Second) * (n.Octets - o.Octets)) / uint64(dur)
		n.PacketsPS = (uint64(time.Second) * (n.Packets - o.Packets)) / uint64(dur)
		n.FlowsPS = (uint64(time.Second) * (n.Flows - o.Flows)) / uint64(dur)
		n.BlockedPS = (uint64(time.Second) * (n.Blocked - o.Blocked)) / uint64(dur)

		for v, _ := range n.VIPs {
			if _, ok := o.VIPs[v]; ok {
				for l, _ := range n.VIPs[v] {
					if _, ok := o.VIPs[v][l]; ok {
						for k, r := range n.VIPs[v][l].Reals {
							if o, ok := o.VIPs[v][l].Reals[k]; ok {
								n.VIPs[v][l].Reals[k] = r.Sub(o, dur)
							}
						}
					}
				}
			}
		}
	}

	for v, _ := range n.VIPs {
		for l, s := range n.VIPs[v] {
			s.Total()
			n.VIPs[v][l] = s
		}
	}

	return n
}
