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
	_ "embed"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/healthchecks"
)

//go:embed static/index.html
var INDEX_HTML []byte

//go:embed static/index.js
var INDEX_JS []byte

type IP4 = vc5.IP4
type L4 = vc5.L4
type Target = vc5.Target

var sock = flag.String("s", "", "help message for flag s")

func main() {
	flag.Parse()
	args := flag.Args()

	if *sock != "" {
		signal.Ignore(syscall.SIGQUIT, syscall.SIGINT)
		vc5.Server(*sock)
		return
	}
	time.Sleep(2 * time.Second)

	temp, err := ioutil.TempFile("/tmp", "prefix")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(temp.Name())

	file := args[0]
	myip := args[1]
	bond := args[2]
	peth := args[3:]

	ip, ok := vc5.ParseIP(myip)

	if !ok {
		log.Fatal(myip)
	}

	conf, err := config2.Load(file, nil)

	if err != nil {
		log.Fatal(err)
	}

	hc, err := healthchecks.ConfHealthchecks(conf)

	vc5, err := vc5.Controller(ip, hc, temp.Name(), bond, peth...)

	if err != nil {
		log.Fatal(err)
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, syscall.SIGQUIT, syscall.SIGINT)

	go func() {
		for {
			switch <-sig {
			default:
				vc5.Close()
				time.Sleep(1 * time.Second)
				log.Fatal("EXITING")
			case syscall.SIGQUIT:
				log.Println("RELOAD")
				time.Sleep(1 * time.Second)

				conf, err = config2.Load(file, conf)

				if err != nil {
					log.Fatal(err)
				}

				hc, err = healthchecks.ConfHealthchecks(conf)

				if err != nil {
					log.Fatal(err)
				}

				vc5.Update(hc)
			}
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) != 1 || r.URL.Path != "/" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write(INDEX_HTML)
	})

	http.HandleFunc("/index.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		w.Write(INDEX_JS)
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
		cf := vc5.Config()
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
		w.WriteHeader(http.StatusOK)

		cf := vc5.Config()
		ss := vc5.Stats()

		var foo Foo
		foo.VIPs = map[IP4]map[L4]map[IP4]Bar{}
		foo.Advertise = map[IP4]bool{}

		for vip, v := range cf.Virtuals {
			foo.VIPs[vip] = map[L4]map[IP4]Bar{}
			foo.Advertise[vip] = v.Healthy
			for l4, s := range v.Services {
				bar := map[IP4]Bar{}
				for n, up := range s.Health {
					r := cf.Backends[n]
					t := Target{VIP: vip, RIP: r.IP, Protocol: l4.Protocol.Number(), Port: l4.Port}
					c := ss[t]
					bar[r.IP] = Bar{Up: up, Octets: c.Octets, Packets: c.Packets}
					foo.Octets += c.Octets
					foo.Packets += c.Packets
				}
				foo.VIPs[vip][l4] = bar
			}
		}

		j, _ := json.MarshalIndent(&foo, "", "  ")
		w.Write(j)
	})

	log.Fatal(http.ListenAndServe(":9999", nil))
}

type Bar struct {
	Up      bool   `json:"up"`
	Octets  uint64 `json:"octets"`
	Packets uint64 `json:"packets"`
}

type Foo struct {
	Octets    uint64
	Packets   uint64
	Advertise map[IP4]bool
	VIPs      map[IP4]map[L4]map[IP4]Bar `json:"vips"`
}
