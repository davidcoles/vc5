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

var sock = flag.String("s", "", "help message for flag s")
var port = flag.String("w", ":9999", "help message for flag w")
var native = flag.Bool("n", false, "help message for flag n")
var testf = flag.Bool("t", false, "help message for flag t")

func main() {
	//test2()
	//return
	//test()
	//return

	flag.Parse()
	args := flag.Args()

	if *testf {
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
	bond := args[2]
	peth := args[3:]

	ip, ok := vc5.ParseIP(myip)

	if !ok {
		log.Fatal(myip)
	}

	conf, err := vc5.LoadConf(file, nil)

	if err != nil {
		log.Fatal(err)
	}

	hc, err := healthchecks.ConfHealthchecks(conf)

	v5, err := vc5.Controller(*native, ip, hc, cmd, temp.Name(), bond, peth...)

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

				conf, err = vc5.LoadConf(file, conf)

				if err != nil {
					log.Fatal(err)
				}

				hc, err = healthchecks.ConfHealthchecks(conf)

				if err != nil {
					log.Fatal(err)
				}

				v5.Update(hc)
			}
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

	var latency []uint64

	http.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		cf := v5.Config()
		ss := v5.Stats()

		var stats Stats
		stats.VIPs = map[IP4]map[L4]map[IP4]Real{}
		stats.Advertise = map[IP4]bool{}

		stats.Packets, stats.Octets, stats.Latency, stats.DEFCON = v5.GlobalStats()

		latency = append(latency, stats.Latency)
		for len(latency) > 10 {
			latency = latency[1:]
		}

		var l uint64

		for _, v := range latency {
			l += v
		}

		l /= uint64(len(latency))

		stats.Latency = l

		log.Printf("DEFCON%d %dns\n", stats.DEFCON, stats.Latency)

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
					//stats.Octets += c.Octets
					//stats.Packets += c.Packets
				}
				stats.VIPs[vip][l4] = reals
			}
		}

		j, _ := json.MarshalIndent(&stats, "", "  ")
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

type Stats struct {
	Octets    uint64                      `json:"octets"`
	Packets   uint64                      `json:"packets"`
	Latency   uint64                      `json:"latency"`
	DEFCON    uint8                       `json:"defcon"`
	Advertise map[IP4]bool                `json:"advertise"`
	VIPs      map[IP4]map[L4]map[IP4]Real `json:"vips"`
}

func test() {
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
	//var nodes [][]byte
	//for i := 0; i < 128; i++ {
	//	s := [4]byte{192, 168, byte(i >> 8), byte(i & 0xff)}
	//	nodes = append(nodes, s[:])
	//}

	for grr := 255; grr > 0; grr-- {

		m := map[[4]byte]uint16{}

		for i := 0; i < grr; i++ {
			s := [4]byte{192, 168, byte(i >> 8), byte(i & 0xff)}
			m[s] = uint16(i)
		}

		var nodes [][]byte

		for k, _ := range m {
			nodes = append(nodes, k[:])
		}

		//s := time.Now()
		table := maglev.Maglev65536(nodes)

		var t2 [65536]uint16

		for k, v := range table {
			i := nodes[v]
			ip := [4]byte{i[0], i[1], i[2], i[3]}
			n, ok := m[ip]
			if !ok {
				panic("poo")
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
