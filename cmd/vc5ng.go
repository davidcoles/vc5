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
// concurrent connections count
// manage existing connection (SYN/RST/etc)
// sticky sessions

package main

import (
	"embed"
	"encoding/json"
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
	"strings"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
	"github.com/davidcoles/vc5/bgp4"
	"github.com/davidcoles/vc5/healthchecks"
)

//go:embed static/*
var STATIC embed.FS

type IP4 = vc5.IP4
type L4 = vc5.L4
type Target = vc5.Target

var dfcn = flag.Uint("d", 5, "defcon readiness level")
var sock = flag.String("s", "", "used when spawning healthcheck server")
var bond = flag.String("i", "", "name of interface to use (eg. bond0, br0)")
var port = flag.String("w", ":9999", "webserver address:port to listen on")
var native = flag.Bool("n", false, "load xdp program in native mode")

func main() {

	flag.Parse()
	args := flag.Args()

	ulimit()

	if *sock != "" {
		signal.Ignore(syscall.SIGQUIT, syscall.SIGINT)
		vc5.NetnsServer(*sock)
		return
	}

	s, err := net.Listen("tcp", *port)

	if err != nil {
		log.Fatal(err)
	}

	temp, err := ioutil.TempFile("/tmp", "prefix")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(temp.Name())

	cmd := []string{os.Args[0], "-s", temp.Name()} // command to run in netns

	file := args[0]
	myip := args[1]
	peth := args[2:]

	mynet, err := vc5.Net(myip)

	if err != nil {
		log.Fatal(err)
	}

	ip := mynet.IP

	conf, err := vc5.LoadConf(file)

	if err != nil {
		log.Fatal(err)
	}

	hc, err := healthchecks.Load(mynet, conf)

	if err != nil {
		log.Fatal(err)
	}

	j, _ := json.MarshalIndent(hc, "", "  ")
	fmt.Println(string(j))

	for _, v := range peth {
		fmt.Println("ethtool", v)
		exec.Command("/bin/sh", "-c", "ethtool -K "+v+" tx off; ethtool -K "+v+" rxvlan off;").Output()
		exec.Command("/bin/sh", "-c", "ethtool -K "+v+" rx off; ethtool -K "+v+" txvlan off;").Output()
	}

	re := regexp.MustCompile("^screen")

	term, ok := os.LookupEnv("TERM")

	if !ok || !re.MatchString(term) {
		log.Fatal("Must run under screen for now for safety")
	}

	v5, err := vc5.Controller(*native, ip, hc, cmd, temp.Name(), *bond, peth...)

	if err != nil {
		log.Fatal(err)
	}

	// temporary auto kill switch
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			v5.DEFCON(0)
		}
	}()

	v5.DEFCON(uint8(*dfcn))

	pool := NewBGPPool(ip, conf.RHI.AS_Number, conf.RHI.Hold_Time, conf.RHI.Communities(), conf.RHI.Peers)

	sig := make(chan os.Signal)
	//signal.Notify(sig, os.Interrupt, syscall.SIGQUIT, syscall.SIGINT)
	signal.Notify(sig)

	go func() {
		for {
			s := <-sig
			switch s {
			case syscall.SIGURG:
			case syscall.SIGCHLD:
			default:
				v5.DEFCON(0)
				v5.Close()
				time.Sleep(1 * time.Second)
				os.Remove(temp.Name())
				log.Fatal("EXITING ", s)
			case syscall.SIGQUIT:
				log.Println("RELOAD")
				time.Sleep(1 * time.Second)

				conf, err = vc5.LoadConf(file)

				if err != nil {
					log.Fatal(err)
				}

				hc, err = hc.Reload(mynet, conf)

				if err != nil {
					log.Fatal(err)
				}

				pool.Peer(conf.RHI.Peers)

				v5.Update(hc)
			}
		}
	}()

	var stats *Stats

	go func() {
		var t time.Time
		start := time.Now()

		for {
			s := getStats(v5)
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "static" + r.URL.Path
		handler.ServeHTTP(w, r)
	})

	http.HandleFunc("/conf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		j, _ := json.MarshalIndent(conf, "", "  ")
		w.Write(j)
	})

	http.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/defcon1", func(w http.ResponseWriter, r *http.Request) {
		v5.DEFCON(1)
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/defcon2", func(w http.ResponseWriter, r *http.Request) {
		v5.DEFCON(2)
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/defcon3", func(w http.ResponseWriter, r *http.Request) {
		v5.DEFCON(3)
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/defcon4", func(w http.ResponseWriter, r *http.Request) {
		v5.DEFCON(4)
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/defcon5", func(w http.ResponseWriter, r *http.Request) {
		v5.DEFCON(5)
		w.WriteHeader(http.StatusOK)
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
		cf := v5.Status()
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
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write(prometheus(stats))
	})

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func getStats(v5 *vc5.VC5) *Stats {

	cf := v5.Status()
	ss := v5.Stats()

	var stats Stats
	stats.VIPs = map[IP4]map[L4]Service{}
	stats.RHI = map[IP4]bool{}

	stats.Packets, stats.Octets, stats.Flows, stats.Latency, stats.DEFCON = v5.GlobalStats()

	for vip, v := range cf.Virtuals {
		stats.VIPs[vip] = map[L4]Service{}
		stats.RHI[vip] = v.Healthy
		for l4, s := range v.Services {
			reals := map[IP4]Real{}
			for n, up := range s.Health {
				r := cf.Backends[n]
				t := Target{VIP: vip, RIP: r.IP, Protocol: l4.Protocol.Number(), Port: l4.Port}
				c := ss[t]
				reals[r.IP] = Real{Up: up, Octets: c.Octets, Packets: c.Packets, Concurrent: c.Concurrent}
			}
			stats.VIPs[vip][l4] = Service{Reals: reals, Up: s.Healthy, Fallback: s.Fallback, Name: s.Metadata.Name, Description: s.Metadata.Description}
		}
	}

	return &stats
}

/**********************************************************************/

type Stats struct {
	Octets    uint64                 `json:"octets"`
	Packets   uint64                 `json:"packets"`
	OctetsPS  uint64                 `json:"octets_ps"`
	PacketsPS uint64                 `json:"packets_ps"`
	Flows     uint64                 `json:"flows"`
	FlowsPS   uint64                 `json:"flows_ps"`
	Latency   uint64                 `json:"latency"`
	DEFCON    uint8                  `json:"defcon"`
	RHI       map[IP4]bool           `json:"rhi"`
	VIPs      map[IP4]map[L4]Service `json:"vips"`
}

type Service struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Up          bool         `json:"up"`
	Fallback    bool         `json:"fallback"`
	Octets      uint64       `json:"octets"`
	Packets     uint64       `json:"packets"`
	OctetsPS    uint64       `json:"octets_ps"`
	PacketsPS   uint64       `json:"packets_ps"`
	Concurrent  uint64       `json:"concurrent"`
	Reals       map[IP4]Real `json:"rips"`
}

func (s *Service) Total() {
	for _, v := range s.Reals {
		s.Octets += v.Octets
		s.Packets += v.Packets
		s.OctetsPS += v.OctetsPS
		s.PacketsPS += v.PacketsPS
		s.Concurrent += v.Concurrent
	}
}

type Real struct {
	Up         bool   `json:"up"`
	Octets     uint64 `json:"octets"`
	Packets    uint64 `json:"packets"`
	OctetsPS   uint64 `json:"octets_ps"`
	PacketsPS  uint64 `json:"packets_ps"`
	Concurrent uint64 `json:"concurrent"`
}

func (r Real) Sub(o Real, dur time.Duration) Real {
	r.OctetsPS = (uint64(time.Second) * (r.Octets - o.Octets)) / uint64(dur)
	r.PacketsPS = (uint64(time.Second) * (r.Packets - o.Packets)) / uint64(dur)
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
func prometheus(g *Stats) []byte {

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
	//m = append(m, fmt.Sprintf("vc5_packets_per_second %d", g.Pps))
	//m = append(m, fmt.Sprintf(`vc5_current_connections %d`, g.Concurrent))
	//m = append(m, fmt.Sprintf("vc5_total_connections %d", g.New_flows))
	m = append(m, fmt.Sprintf("vc5_rx_packets %d", g.Packets))
	m = append(m, fmt.Sprintf("vc5_rx_octets %d", g.Octets))
	//m = append(m, fmt.Sprintf("vc5_userland_queue_failed %d", g.Qfailed))
	m = append(m, fmt.Sprintf("vc5_defcon %d", g.DEFCON))

	for i, v := range g.RHI {
		m = append(m, fmt.Sprintf(`vc5_rhi{address="%s"} %d`, i, b2u8(v)))
	}

	for vip, services := range g.VIPs {
		for l4, v := range services {
			//d := v.Description
			s := vip.String() + ":" + l4.String()
			n := v.Name
			m = append(m, fmt.Sprintf(`vc5_service_current_connections{service="%s",sname="%s"} %d`, s, n, v.Concurrent))
			//m = append(m, fmt.Sprintf(`vc5_service_total_connections{service="%s",sname="%s"} %d`, s, n, v.New_flows))
			m = append(m, fmt.Sprintf(`vc5_service_rx_packets{service="%s",sname="%s"} %d`, s, n, v.Packets))
			m = append(m, fmt.Sprintf(`vc5_service_rx_octets{service="%s",sname="%s"} %d`, s, n, v.Octets))

			m = append(m, fmt.Sprintf(`vc5_service_healthcheck{service="%s",sname="%s"} %d`, s, n, b2u8(v.Up)))

			for b, v := range v.Reals {
				m = append(m, fmt.Sprintf(`vc5_backend_current_connections{service="%s",backend="%s"} %d`, s, b, v.Concurrent))
				//m = append(m, fmt.Sprintf(`vc5_backend_total_connections{service="%s",backend="%s"} %d`, s, b, v.New_flows))
				m = append(m, fmt.Sprintf(`vc5_backend_rx_packets{service="%s",backend="%s"} %d`, s, b, v.Packets))
				m = append(m, fmt.Sprintf(`vc5_backend_rx_octets{service="%s",backend="%s"} %d`, s, b, v.Octets))

				m = append(m, fmt.Sprintf(`vc5_backend_healthcheck{service="%s",backend="%s"} %d`, s, b, b2u8(v.Up)))
			}
		}
	}

	all := strings.Join(m, "\n")
	return []byte(all)
}

/**********************************************************************/

type BGPPool struct {
	nlri chan map[IP4]bool
	peer chan []string
	wait chan bool
}

func NewBGPPool(rid [4]byte, asn uint16, hold uint16, communities []uint32, peer []string) *BGPPool {
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

func (b *BGPPool) manage(rid [4]byte, asn uint16, hold uint16, communities []uint32) {

	nlri := map[IP4]bool{}
	peer := map[string]*bgp4.Peer{}

	for {
		select {
		case n := <-b.nlri:

			if !diff(n, nlri) {
				break
			}

			fmt.Println("*******", n, peer)

			for k, v := range peer {
				for ip, up := range n {
					fmt.Println("NLRI", ip, up, "to", k)
					v.NLRI(bgp4.IP4(ip), up)
				}
			}

			nlri = n

		case p := <-b.peer:
			fmt.Println("************************************************** PEER", p)

			m := map[string]*bgp4.Peer{}

			for _, s := range p {

				if v, ok := peer[s]; ok {
					m[s] = v
					delete(peer, s)
				} else {
					v = bgp4.Session(s, rid, rid, asn, hold, communities, b.wait, nil)
					m[s] = v
					for k, v := range peer {
						for ip, up := range nlri {
							fmt.Println("NLRI", ip, up, "to", k)
							v.NLRI(bgp4.IP4(ip), up)
						}
					}
				}
			}

			for k, v := range peer {
				fmt.Println("close", k, v)
				v.Close()
			}

			peer = m
		}
	}
}
