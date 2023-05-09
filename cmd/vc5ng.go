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
// time since last state change for reals/services/vips

// When:
// * adding a new vip, all checks should start in down state to prevent traffic being sent to the LB
// * adding a new service to an existing vip, service should start in "up" state to prevent vip being withdrawn (chaos)
// * adding a new real to an existing service, host checks should start in "down" state to prevent hash being changed

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

func main() {

	start := time.Now()

	flag.Parse()
	args := flag.Args()

	ulimit()

	if *sock != "" {
		//signal.Ignore(syscall.SIGQUIT, syscall.SIGINT)
		//signal.Ignore(syscall.SIGHUP)
		signal.Ignore(syscall.SIGUSR2, syscall.SIGQUIT)
		vc5.NetnsServer(*sock)
		return
	}

	file := args[0]
	myip := args[1]
	peth := args[2:]

	ip := net.ParseIP(myip)

	if ip == nil {
		log.Fatal("IP is nil")
	}

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

	mynic := *bond

	if mynic == "" {
		mynic = peth[0]
	}

	if err != nil {
		log.Fatal(err)
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

	//err = lb.Start(mynet.IP, hc)
	err = lb.Start(myip, hc)

	if err != nil {
		log.Fatal(err)
	}

	//pool := NewBGPPool(mynet.IP, conf.RHI.AS_Number, conf.RHI.Hold_Time, conf.RHI.Communities(), conf.RHI.Peers)
	pool := NewBGPPool(ip, conf.RHI.AS_Number, conf.RHI.Hold_Time, conf.RHI.Communities(), conf.RHI.Peers, conf.RHI.Listen)

	sig := make(chan os.Signal)
	//signal.Notify(sig, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGQUIT)
	//signal.Notify(sig)  // alll

	go func() {
		for {
			s := <-sig
			switch s {
			case syscall.SIGQUIT:
				fallthrough
			case syscall.SIGUSR2:
				log.Println("RELOAD")
				time.Sleep(1 * time.Second)

				conf, err := vc5.LoadConf(file)

				if err != nil {
					log.Println(err)
				} else {

					h, err := hc.Reload(conf)

					if err != nil {
						log.Println(err)
					} else {

						pool.Peer(conf.RHI.Peers)

						hc = h
						lb.Update(hc)
					}
				}
			}
		}
	}()

	var stats *Stats

	go func() {
		var t time.Time
		start := time.Now()

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

	static := http.FS(STATIC)
	handler := http.FileServer(static)
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

		switch r.URL.Path {
		case "/defcon1":
			defcon(w, r, lb, 1)
			return
		case "/defcon2":
			defcon(w, r, lb, 2)
			return
		case "/defcon3":
			defcon(w, r, lb, 3)
			return
		case "/defcon4":
			defcon(w, r, lb, 4)
			return
		case "/defcon5":
			defcon(w, r, lb, 5)
			return
		}

		r.URL.Path = "static/" + r.URL.Path // there must be a way to avoid this, surely ...
		handler.ServeHTTP(w, r)
	})

	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		for _, l := range logger.Dump() {
			w.Write([]byte(fmt.Sprintln(l)))
		}
	})

	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		j, err := json.MarshalIndent(hc, "", "  ")

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(j)
	})

	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cf := lb.Status()
		j, err := json.MarshalIndent(cf, "", "  ")

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(j)
	})

	http.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		j, _ := json.MarshalIndent(stats, "", "  ")

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(j)
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if stats == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write(prometheus(stats, start))
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

func defcon(w http.ResponseWriter, r *http.Request, lb *vc5.LoadBalancer, d uint8) {

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
}

func getStats(lb *vc5.LoadBalancer) *Stats {

	now := time.Now()

	status := lb.Status()
	global, counters := lb.Stats()

	//j, _ := json.MarshalIndent(cf, "", "  ")
	//fmt.Println(string(j))

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

/**********************************************************************/

func ulimit() {
	var rLimit syscall.Rlimit
	RLIMIT_MEMLOCK := 8
	if err := syscall.Getrlimit(RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatal("Error Getting Rlimit ", err)
	}
	rLimit.Max = 0xffffffffffffffff
	rLimit.Cur = 0xffffffffffffffff
	if err := syscall.Setrlimit(RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatal("Error Setting Rlimit ", err)
	}
}

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

	//m = append(m, fmt.Sprintf("vc5_packets_per_second %d", g.PacketsPS))

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

type BGPPool struct {
	nlri chan map[IP4]bool
	peer chan []string
	wait chan bool
}

func NewBGPPool(ip net.IP, asn uint16, hold uint16, communities []uint32, peer []string, listen bool) *BGPPool {
	var rid IP4

	if listen {
		go func() {
			for {
				bgpListen()
				time.Sleep(60 * time.Second)
			}
		}()
	}

	foo := ip.To4()

	if foo == nil {
		log.Fatal("oops")
	}

	copy(rid[:], foo[:])

	b := &BGPPool{nlri: make(chan map[IP4]bool), peer: make(chan []string), wait: make(chan bool)}
	go b.manage(rid, asn, hold, communities)
	b.peer <- peer
	close(b.wait)
	return b
}

func (b *BGPPool) NLRI(n map[IP4]bool) {
	b.nlri <- n
}

func (b *BGPPool) Peer(p []string) {
	b.peer <- p
}

func diff(a, b map[IP4]bool) bool {
	for k, v := range a {
		if x, ok := b[k]; !ok || x != v {
			return true
		}
	}
	for k, v := range b {
		if x, ok := a[k]; !ok || x != v {
			return true
		}
	}
	return false
}

func bgpListen() {
	l, err := net.Listen("tcp", ":179")
	if err != nil {
		//logs.NOTICE("BGP4 listen failed", err)
		return
	}

	//logs.WARNING("Listening:", l)

	defer l.Close()

	for {
		conn, err := l.Accept()

		if err != nil {
			//logs.INFO("BGP4 connection failed", err)
		} else {
			go func(c net.Conn) {
				//logs.WARNING("Accepted conn:", c)
				defer c.Close()
				time.Sleep(time.Minute)
				//logs.WARNING("Quitting", c)
			}(conn)
		}
	}
}

func (b *BGPPool) manage(rid [4]byte, asn uint16, hold uint16, communities []uint32) {

	nlri := map[IP4]bool{}
	peer := map[string]*bgp4.Peer{}

	for {
		select {
		case n := <-b.nlri:

			if !diff(n, nlri) {
				break
			}

			//fmt.Println("*******", n, peer)

			for k, v := range peer {
				for ip, up := range n {
					fmt.Println("NLRI", ip, up, "to", k)
					logger.NOTICE("peers", "NLRI", ip, up, "to", k)
					v.NLRI(bgp4.IP4(ip), up)
				}
			}

			nlri = n

		case p := <-b.peer:
			//fmt.Println("************************************************** PEER", p)

			m := map[string]*bgp4.Peer{}

			for _, s := range p {

				if v, ok := peer[s]; ok {
					m[s] = v
					delete(peer, s)
				} else {
					h := hold
					if h == 0 {
						h = 4
					}

					v = bgp4.Session(s, rid, rid, asn, h, communities, b.wait, nil)
					m[s] = v
					//for k, v := range peer {
					for ip, up := range nlri {
						//fmt.Println("peers", "NLRI", ip, up, "to", s)
						logger.NOTICE("peers", "NLRI", ip, up, "to", s)
						v.NLRI(bgp4.IP4(ip), up)
					}
					//}
				}
			}

			for k, v := range peer {
				logger.NOTICE("peers", "close", k, v)
				v.Close()
			}

			peer = m
		}
	}
}

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
