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
// BGP
// VLANs
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
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/maglev"
	"github.com/davidcoles/vc5/rendezvous"
)

//go:embed static/*
var STATIC embed.FS

type IP4 = vc5.IP4
type L4 = vc5.L4
type Target = vc5.Target

var sock = flag.String("s", "", "used when spawning healthcheck server")
var bond = flag.String("b", "", "name of bonded ethernet device if using multiple interfaces")
var port = flag.String("w", ":9999", "webserver address:port to listen on")
var native = flag.Bool("n", false, "load xdp program in native mode")
var test = flag.Bool("t", false, "run hashing tests")

func main() {

	flag.Parse()
	args := flag.Args()

	if *test {
		test3()
		return
	}

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

	ip, ok := vc5.ParseIP(myip)

	if !ok {
		log.Fatal(myip)
	}

	conf, err := vc5.LoadConf(file)

	if err != nil {
		log.Fatal(err)
	}

	hc, err := healthchecks.Load(conf)

	if err != nil {
		log.Fatal(err)
	}

	v5, err := vc5.Controller(*native, ip, hc, cmd, temp.Name(), *bond, peth...)

	if err != nil {
		log.Fatal(err)
	}

	pool := NewBGPPool(conf.RHI.AS_Number, conf.RHI.Hold_Time, conf.RHI.Peers)
	pool.Peer(conf.RHI.Peers)

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, syscall.SIGQUIT, syscall.SIGINT)

	go func() {
		for {
			switch <-sig {
			default:
				v5.Close()
				time.Sleep(1 * time.Second)
				os.Remove(temp.Name())
				log.Fatal("EXITING")
			case syscall.SIGQUIT:
				log.Println("RELOAD")
				time.Sleep(1 * time.Second)

				conf, err = vc5.LoadConf(file)

				if err != nil {
					log.Fatal(err)
				}

				hc, err = hc.Reload(conf)

				if err != nil {
					log.Fatal(err)
				}

				pool.Peer(conf.RHI.Peers)

				v5.Update(hc)
			}
		}
	}()

	var stats *Stats

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

	go func() {
		var t time.Time

		for {
			s := getStats(v5)
			s.Sub(stats, time.Now().Sub(t))
			t = time.Now()
			stats = s
			pool.NLRI(s.RHI)
			time.Sleep(1 * time.Second)
		}
	}()

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func getStats(v5 *vc5.VC5) *Stats {

	cf := v5.Status()
	ss := v5.Stats()

	var stats Stats
	stats.VIPs = map[IP4]map[L4]Service{}
	stats.RHI = map[IP4]bool{}

	stats.Packets, stats.Octets, stats.Latency, stats.DEFCON = v5.GlobalStats()

	for vip, v := range cf.Virtuals {
		stats.VIPs[vip] = map[L4]Service{}
		stats.RHI[vip] = v.Healthy
		for l4, s := range v.Services {
			reals := map[IP4]Real{}
			for n, up := range s.Health {
				r := cf.Backends[n]
				t := Target{VIP: vip, RIP: r.IP, Protocol: l4.Protocol.Number(), Port: l4.Port}
				c := ss[t]
				reals[r.IP] = Real{Up: up, Octets: c.Octets, Packets: c.Packets}
			}
			stats.VIPs[vip][l4] = Service{Reals: reals, Up: s.Healthy, Fallback: s.Fallback}
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
	Latency   uint64                 `json:"latency"`
	DEFCON    uint8                  `json:"defcon"`
	RHI       map[IP4]bool           `json:"rhi"`
	VIPs      map[IP4]map[L4]Service `json:"vips"`
}

type Service struct {
	Up        bool         `json:"up"`
	Fallback  bool         `json:"fallback"`
	Octets    uint64       `json:"octets"`
	Packets   uint64       `json:"packets"`
	OctetsPS  uint64       `json:"octets_ps"`
	PacketsPS uint64       `json:"packets_ps"`
	Reals     map[IP4]Real `json:"rips"`
}

func (s *Service) Total() {
	for _, v := range s.Reals {
		s.Octets += v.Octets
		s.Packets += v.Packets
		s.OctetsPS += v.OctetsPS
		s.PacketsPS += v.PacketsPS
	}
}

type Real struct {
	Up        bool   `json:"up"`
	Octets    uint64 `json:"octets"`
	Packets   uint64 `json:"packets"`
	OctetsPS  uint64 `json:"octets_ps"`
	PacketsPS uint64 `json:"packets_ps"`
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

func test1() {
	//log.Fatal(xdp.BpfNumPossibleCpus())
	x, xx := rendezvous.Test(100)

	d := map[byte]int{}

	for _, v := range x {
		d[v] = d[v] + 1
	}

	h := []int{}

	max := 0

	for _, v := range d {
		if v > max {
			max = v
		}
		h = append(h, v)
	}

	fmt.Println(max)
	sort.Ints(h)

	for _, v := range h {
		fmt.Printf("%03d ", v)
		for n := 0; n < ((v * 80) / max); n++ {
			fmt.Print("#")
		}
		fmt.Println()
	}

	fmt.Println(xx)

	return
}

func test2() {

	for n := 255; n > 0; n-- {

		m := map[[4]byte]uint16{}

		for i := 0; i < n; i++ {
			s := [4]byte{192, 168, byte(i >> 8), byte(i & 0xff)}
			m[s] = uint16(i)
		}

		var nodes [][]byte

		for k, _ := range m {
			nodes = append(nodes, k[:])
		}

		table := maglev.Maglev8192(nodes)

		var t2 [8192]uint16

		for k, v := range table {
			i := nodes[v]
			ip := [4]byte{i[0], i[1], i[2], i[3]}
			n, ok := m[ip]
			if !ok {
				panic("oops")
			}

			t2[k] = n
		}
		//d := time.Now().Sub(s)

		//fmt.Println(d)

		dst := map[uint16]int{}
		max := 0

		for _, v := range table {
			g := uint16(v)
			dst[g] = dst[g] + 1
			if dst[g] > max {
				max = dst[g]
			}
		}

		for k, v := range dst {
			//fmt.Println(k, v)

			fmt.Printf("%03d ", k)
			for n := 0; n < ((v * 80) / max); n++ {
				fmt.Print("#")
			}
			fmt.Println()
		}
	}
}

func test3() {

	for n := 255; n > 0; n-- {

		m := map[[4]byte][6]byte{}

		for i := 0; i < n; i++ {
			s := [4]byte{192, 168, byte(i >> 8), byte(i & 0xff)}
			m[s] = [6]byte{}
		}

		table, stats := maglev.IP(m)
		fmt.Println(stats, table[0:54])

		if stats.Variance > 7 {
			panic("oops")
		}
	}
}

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

type BGPPool struct {
	nlri chan map[IP4]bool
	peer chan []string
}

func NewBGPPool(asn uint16, hold uint16, peer []string) *BGPPool {
	b := &BGPPool{nlri: make(chan map[IP4]bool), peer: make(chan []string)}
	go b.manage()
	b.peer <- peer
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

func (b *BGPPool) manage() {

	nlri := map[IP4]bool{}
	peer := map[string]bool{}

	for {
		select {
		case n := <-b.nlri:

			if !diff(n, nlri) {
				break
			}

			for k, v := range peer {
				fmt.Println("NLRI", k, v, nlri, "to", n)
				//v <- nlri
			}

			nlri = n

		case p := <-b.peer:
			fmt.Println("************************************************** PEER", p)

			m := map[string]bool{}

			for _, s := range p {

				if v, ok := peer[s]; ok {
					m[s] = v
					delete(peer, s)
				} else {
					m[s] = true
				}
			}

			for k, v := range peer {
				fmt.Println("close", k, v)
				//close(v)
			}

			peer = m
		}
	}
}
