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
// concurrent connections
// manage existing connection (SYN/RST/etc)
// BGP
// VLANs
// sticky

package main

import (
	"embed"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
	"github.com/davidcoles/vc5/healthchecks"

	//"github.com/davidcoles/vc5/xdp"
	"fmt"
	"github.com/davidcoles/vc5/maglev"
	"github.com/davidcoles/vc5/rendezvous"
	"sort"
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
	//test2()
	//return
	//test1()
	//return

	flag.Parse()
	args := flag.Args()

	if *test {
		test2()
		return
	}

	if *sock != "" {
		signal.Ignore(syscall.SIGQUIT, syscall.SIGINT)
		vc5.NetnsServer(*sock)
		return
	}
	//time.Sleep(2 * time.Second)

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

				v5.Update(hc)
			}
		}
	}()

	var stats *Stats

	go func() {
		var latency []uint64
		var n *Stats
		var o *Stats
		var t time.Time

		for {
			o = n
			n = getStats(v5)

			r := n.Sub(o, time.Now().Sub(t))
			t = time.Now()

			r.Latency, latency = Latency(n.Latency, latency)

			stats = r

			time.Sleep(1 * time.Second)
		}
	}()

	static := http.FS(STATIC)
	handler := http.FileServer(static)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "static" + r.URL.Path
		handler.ServeHTTP(w, r)
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
		cf := v5.Config()
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

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

type Real struct {
	Up      bool   `json:"up"`
	Octets  uint64 `json:"octets"`
	Packets uint64 `json:"packets"`
}

func (r Real) Sub(o Real, dur time.Duration) Real {

	d := uint64(dur)

	var n Real
	n.Up = r.Up
	n.Octets = (uint64(time.Second) * (r.Octets - o.Octets)) / d
	n.Packets = (uint64(time.Second) * (r.Packets - o.Packets)) / d
	return n
}

type Stats struct {
	Octets    uint64                      `json:"octets"`
	Packets   uint64                      `json:"packets"`
	Latency   uint64                      `json:"latency"`
	DEFCON    uint8                       `json:"defcon"`
	Advertise map[IP4]bool                `json:"advertise"`
	VIPs      map[IP4]map[L4]map[IP4]Real `json:"vips"`
}

func (n *Stats) Sub(o *Stats, dur time.Duration) *Stats {

	d := uint64(dur)

	var r Stats

	r.VIPs = map[IP4]map[L4]map[IP4]Real{}

	if o != nil {

		r.Octets = (uint64(time.Second) * (n.Octets - o.Octets)) / d
		r.Packets = (uint64(time.Second) * (n.Packets - o.Packets)) / d
		r.Latency = n.Latency
		r.DEFCON = n.DEFCON

		for v, _ := range n.VIPs {
			r.VIPs[v] = map[L4]map[IP4]Real{}
			if _, ok := o.VIPs[v]; ok {
				for l, _ := range n.VIPs[v] {
					if _, ok := o.VIPs[v][l]; ok {
						r.VIPs[v][l] = map[IP4]Real{}
						for k, n := range n.VIPs[v][l] {
							if o, ok := o.VIPs[v][l][k]; ok {
								r.VIPs[v][l][k] = n.Sub(o, dur)
							}
						}
					}
				}
			}
		}
	}

	return &r
}

func Latency(l uint64, latency []uint64) (uint64, []uint64) {

	latency = append(latency, l)

	for len(latency) > 10 {
		latency = latency[1:]
	}

	l = 0

	for _, v := range latency {
		l += v
	}

	l /= uint64(len(latency))

	return l, latency
}

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

		table := maglev.Maglev65536(nodes)

		var t2 [65536]uint16

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

func getStats(v5 *vc5.VC5) *Stats {

	cf := v5.Config()
	ss := v5.Stats()

	var stats Stats
	stats.VIPs = map[IP4]map[L4]map[IP4]Real{}
	stats.Advertise = map[IP4]bool{}

	stats.Packets, stats.Octets, stats.Latency, stats.DEFCON = v5.GlobalStats()

	for vip, v := range cf.Virtuals {
		stats.VIPs[vip] = map[L4]map[IP4]Real{}
		stats.Advertise[vip] = v.Healthy
		for l4, s := range v.Services {
			reals := map[IP4]Real{}
			for n, up := range s.Health {
				r := cf.Backends[n]
				t := Target{VIP: vip, RIP: r.IP, Protocol: l4.Protocol.Number(), Port: l4.Port}
				c := ss[t]
				reals[r.IP] = Real{Up: up, Octets: c.Octets, Packets: c.Packets}
			}
			stats.VIPs[vip][l4] = reals
		}
	}

	return &stats
}
