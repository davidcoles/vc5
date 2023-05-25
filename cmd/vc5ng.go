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

// TODO
// manage existing connection (SYN/RST/etc)
// sticky sessions
// BGP stats/state
// MAC address uniqueness check
// clean up tag/multinic
// add warning for untagged hosts

package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	//"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
	"github.com/davidcoles/vc5/bgp4"
)

var logger *Logger

//go:embed static/*
var STATIC embed.FS

type IP4 = vc5.IP4
type L4 = vc5.L4
type Target = vc5.Target

var level = flag.Uint("l", LOG_ERR, "debug level level")
var kill = flag.Uint("k", 0, "killswitch engage - automatic shutoff after k minutes")
var dfcn = flag.Uint("d", 5, "defcon readiness level")
var auth = flag.String("a", "", "user auth")
var sock = flag.String("s", "", "unix domain socket to use when spawning healthcheck server")
var bond = flag.String("i", "", "name of egress interface to use (eg. bond0)")
var root = flag.String("r", "", "webserver root directory")
var websrv = flag.String("w", ":9999", "webserver address:port to listen on")
var native = flag.Bool("n", false, "load xdp program in native mode")
var multi = flag.Bool("m", false, "multi-nic mode")
var nolabel = flag.Bool("N", false, "don't add 'name' label to prometheus metrics")

const RLIMIT_MEMLOCK = 8

func ulimit(resource int) {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(resource, &rLimit); err != nil {
		log.Fatal("Error Getting Rlimit ", err)
	}
	rLimit.Max = 0xffffffffffffffff
	rLimit.Cur = 0xffffffffffffffff
	if err := syscall.Setrlimit(resource, &rLimit); err != nil {
		log.Fatal("Error Setting Rlimit ", err)
	}
}

func main() {

	flag.Parse()
	args := flag.Args()

	if *sock != "" {
		signal.Ignore(syscall.SIGUSR2, syscall.SIGQUIT)
		vc5.NetnsServer(*sock)
		return
	}

	ulimit(RLIMIT_MEMLOCK)

	file := args[0]
	addr := args[1]
	peth := args[2:]

	conf, err := vc5.LoadConf(file)

	if err != nil {
		log.Fatal(err)
	}

	if false {
		j, _ := json.MarshalIndent(conf, "", "  ")
		fmt.Println(string(j))
		return
	}

	if conf.Webserver != "" {
		*websrv = conf.Webserver
	}

	s, err := net.Listen("tcp", *websrv)

	if err != nil {
		log.Fatal(err)
	}

	temp, err := ioutil.TempFile("/tmp", "prefix")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(temp.Name())

	for _, v := range peth {
		exec.Command("/bin/sh", "-c", "ethtool -K "+v+" tx off; ethtool -K "+v+" rxvlan off;").Output()
		exec.Command("/bin/sh", "-c", "ethtool -K "+v+" rx off; ethtool -K "+v+" txvlan off;").Output()
	}

	hc, err := vc5.Load(conf)

	if err != nil {
		log.Fatal(err)
	}

	if false {
		j, _ := json.MarshalIndent(hc, "", "  ")
		fmt.Println(string(j))
		return
	}

	logger = &Logger{Level: uint8(*level)}

	pool := bgp4.Pool{
		Address:     addr,
		ASN:         conf.RHI.AS_Number,
		HoldTime:    conf.RHI.Hold_Time,
		Communities: conf.RHI.Community(),
		Peers:       conf.RHI.Peers,
		Listen:      conf.RHI.Listen,
	}

	if !pool.Open() {
		log.Fatal("BGP peer initialisation failed")
	}

	lb := &vc5.LoadBalancer{
		ReadinessLevel:  uint8(*dfcn),
		KillSwitch:      *kill,
		Native:          *native,
		MultiNIC:        *multi,
		Socket:          temp.Name(),
		NetnsCommand:    []string{os.Args[0], "-s", temp.Name()},
		Interfaces:      peth,
		EgressInterface: *bond,
		Logger:          logger,
	}

	err = lb.Start(addr, hc)

	if err != nil {
		log.Fatal(err)
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGQUIT)
	//signal.Notify(sig) // all the signals!

	go func() {
		for {
			s := <-sig
			switch s {
			case syscall.SIGQUIT:
				fallthrough
			case syscall.SIGUSR2:
				log.Println("RELOAD")
				time.Sleep(1 * time.Second)

				conf, err := lb.LoadConf(file)

				if err != nil {
					log.Println(err)
				} else {
					if h, err := hc.Reload(conf); err != nil {
						log.Println(err)
					} else {
						hc = h
						pool.Peer(conf.RHI.Peers)
						lb.Update(hc)
					}
				}
			}
		}
	}()

	var stats *Stats
	start := time.Now()

	go func() {
		var t time.Time

		for {
			s := getStats(lb)
			s.Sub(stats, time.Now().Sub(t))
			t = time.Now()
			stats = s
			if time.Now().Sub(start) > (time.Duration(conf.Learn) * time.Second) {
				pool.NLRI(s.RHI)
			}
			time.Sleep(1 * time.Second)
		}
	}()

	var timestamp time.Time
	var mutex sync.Mutex
	prefixes := []byte("{}")

	static := http.FS(STATIC)
	var fs http.FileSystem

	if *root != "" {
		fs = http.FileSystem(http.Dir(*root))
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if fs != nil {
			file := r.URL.Path
			if file == "" || file == "/" {
				file = "/index.html"
			}

			if f, err := fs.Open("/" + file); err == nil {
				f.Close()
				http.FileServer(fs).ServeHTTP(w, r)
				return
			}
		}

		if defcon(w, r, lb) {
			return
		}

		r.URL.Path = "static/" + r.URL.Path // there must be a way to avoid this, surely ...
		http.FileServer(static).ServeHTTP(w, r)
	})

	http.HandleFunc("/prefixes.json", func(w http.ResponseWriter, r *http.Request) {

		mutex.Lock()
		defer mutex.Unlock()
		now := time.Now()

		if now.Sub(timestamp) > (time.Second * 50) {
			p := lb.Prefixes()
			j, err := json.Marshal(p)

			if err != nil {
				prefixes = []byte("{}")
			} else {
				prefixes = j
			}

			timestamp = now
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(prefixes)
	})

	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		for _, l := range logger.Dump() {
			w.Write([]byte(fmt.Sprintln(l)))
		}
	})

	http.HandleFunc("/conf.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, err := json.MarshalIndent(conf, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, err := json.MarshalIndent(hc, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cf := lb.Status()
		j, err := json.MarshalIndent(cf, "", "  ")

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, _ := json.MarshalIndent(stats, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if stats == nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write(prometheus(stats, start))
		}
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		history := logger.Dump()

		re := regexp.MustCompile("^/log/([0-9]+)$")
		match := re.FindStringSubmatch(r.RequestURI)

		if match != nil && len(match) == 2 {
			n, _ := strconv.ParseInt(match[1], 10, 64)
			history = logger.Since(int64(n))
		}

		if j, err := json.MarshalIndent(history, "", "  "); err != nil {
			log.Println(err)
			w.Write([]byte(`[]`))
		} else {
			w.Write(j)
		}
		w.Write([]byte("\n"))
	})

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func defcon(w http.ResponseWriter, r *http.Request, lb *vc5.LoadBalancer) (ret bool) {

	var d uint8

	switch r.URL.Path {
	case "/defcon1":
		d = 1
	case "/defcon2":
		d = 2
	case "/defcon3":
		d = 3
	case "/defcon4":
		d = 4
	case "/defcon5":
		d = 5
	}

	if d == 0 {
		return
	}

	ret = true

	switch *auth {
	case "":
		w.WriteHeader(http.StatusNotFound)
		return
	case ":":
	default:
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(*auth))
		authorization, ok := r.Header["Authorization"]

		if !ok || len(authorization) < 1 || authorization[0] != basic {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	lb.DEFCON(d)
	w.WriteHeader(http.StatusOK)
	return
}

func getStats(lb *vc5.LoadBalancer) *Stats {

	now := time.Now()
	status := lb.Status()
	global, counters := lb.Stats()
	stats := Stats{
		Octets:  global.Octets,
		Packets: global.Packets,
		Flows:   global.Flows,
		Latency: global.Latency,
		DEFCON:  global.DEFCON,
		VIPs:    map[IP4]map[L4]Service{},
		RHI:     map[IP4]bool{},
		When:    map[IP4]int64{},
	}

	for vip, v := range status.Virtual {
		stats.VIPs[vip] = map[L4]Service{}
		stats.RHI[vip] = v.Healthy
		stats.When[vip] = int64(now.Sub(v.Change) / time.Second)
		for l4, s := range v.Services {
			reals := map[IP4]Real{}

			var servers uint8
			var healthy uint8

			for rip, real := range s.Reals {
				servers++

				if real.Probe.Passed {
					healthy++
				}

				t := Target{VIP: vip, RIP: rip, Protocol: l4.Protocol.Number(), Port: l4.Port}
				c := counters[t]

				stats.Concurrent += c.Concurrent

				reals[rip] = Real{
					Up:         real.Probe.Passed,
					When:       int64(time.Now().Sub(real.Probe.Time) / time.Second),
					Message:    real.Probe.Message,
					Duration:   int64(real.Probe.Duration / time.Millisecond),
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
		m = append(m, fmt.Sprintf(`vc5_vip_status{vip="%s"} %d`, i, b2u8(g.RHI[i])))
		m = append(m, fmt.Sprintf(`vc5_vip_status_duration{vip="%s",status="%s"} %d`, i, updown(g.RHI[i]), v))
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
	Concurrent uint64                 `json:"concurrent"`
	Latency    uint64                 `json:"latency"`
	DEFCON     uint8                  `json:"defcon"`
	RHI        map[IP4]bool           `json:"rhi"`
	When       map[IP4]int64          `json:"when"`
	VIPs       map[IP4]map[L4]Service `json:"vips"`
}

type Service struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Up          bool         `json:"up"`
	When        int64        `json:"when"`
	Fallback    bool         `json:"fallback"`
	FallbackOn  bool         `json:"fallback_on"`
	FallbackUp  bool         `json:"fallback_up"`
	Octets      uint64       `json:"octets"`
	OctetsPS    uint64       `json:"octets_ps"`
	Packets     uint64       `json:"packets"`
	PacketsPS   uint64       `json:"packets_ps"`
	Flows       uint64       `json:"flows"`
	FlowsPS     uint64       `json:"flows_ps"`
	Concurrent  uint64       `json:"concurrent"`
	Reals       map[IP4]Real `json:"rips"`
	Minimum     uint8        `json:"minimum"`
	Servers     uint8        `json:"servers"`
	Healthy     uint8        `json:"healthy"`
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
