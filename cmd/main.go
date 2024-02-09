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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	//"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/bgp"
	"github.com/davidcoles/cue/mon"

	lb "github.com/davidcoles/xvs"
)

// TODO:

//go:embed static/*
var STATIC embed.FS

func main() {
	F := "vc5"

	//fmt.Println(debug.ReadBuildInfo())

	var mutex sync.Mutex

	start := time.Now()
	root := flag.String("r", "", "webserver root directory")
	sock := flag.String("s", "", "socket")
	native := flag.Bool("n", false, "Native mode XDP")
	redirect := flag.Bool("R", false, "Redirect mode")
	webserver := flag.String("w", ":80", "webserver listen address")
	elasticsearch := flag.Bool("e", false, "Elasticsearch logging")

	flag.Parse()

	args := flag.Args()

	if *sock != "" {
		// we're going to be the server running in the network namespace ...
		signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
		netns(*sock, netip.MustParseAddr(args[0]))
		return
	}

	logs := &logger{elastic: *elasticsearch}

	socket, err := ioutil.TempFile("/tmp", "vc5ns")

	if err != nil {
		logs.EMERG(F, "socket", err)
		log.Fatal(err)
	}

	defer os.Remove(socket.Name())

	file := args[0]
	addr := netip.MustParseAddr(args[1])
	nics := args[2:]

	if !addr.Is4() {
		logs.EMERG(F, "Address is not IPv4:", addr)
		log.Fatal("Address is not IPv4: ", addr)
	}

	config, err := Load(file)

	if err != nil {
		logs.EMERG(F, "Couldn't load config file:", config, err)
		log.Fatal("Couldn't load config file:", config, err)
	}

	if config.Webserver != "" {
		*webserver = config.Webserver
	}

	client := &lb.Client{
		Interfaces: nics,
		Address:    addr,
		Redirect:   *redirect,
		Native:     *native,
		VLANs:      config.vlans(),
		NAT:        true,
		Logger:     logs.sub("xvs"),
		Share:      config.Multicast != "",
	}

	err = client.Start()

	if err != nil {
		logs.EMERG(F, "Couldn't start client:", err)
		log.Fatal(err)
	}

	if config.Multicast != "" {
		go multicast_send(client, config.Multicast)
		go multicast_recv(client, config.Multicast)
	}

	pool := bgp.NewPool(addr.As4(), config.BGP, nil, logs.sub("bgp"))

	if pool == nil {
		log.Fatal("BGP pool fail")
	}

	go spawn(logs, client.Namespace(), os.Args[0], "-s", socket.Name(), client.NamespaceAddress())

	af_unix := unix(socket.Name())

	director := &cue.Director{
		Logger: logs.sub("director"),
		Balancer: &Balancer{
			Client: client,
			ProbeFunc: func(vip, rip, nat netip.Addr, check mon.Check) (bool, string) {
				return probe(af_unix, vip, rip, nat, check, logs)
			},
		},
	}

	err = director.Start(config.parse())

	if err != nil {
		logs.EMERG(F, "Couldn't start director:", err)
		log.Fatal(err)
	}

	done := make(chan bool)

	vip := map[netip.Addr]State{}

	var rib []netip.Addr
	var summary Summary

	services, old, _ := serviceStatus(config, client, director, nil)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			mutex.Lock()
			summary.update(client, uint64(time.Now().Sub(start)/time.Second))
			services, old, summary.Current = serviceStatus(config, client, director, old)
			mutex.Unlock()
			select {
			case <-ticker.C:
			case <-done:
				return
			}
		}
	}()

	go func() { // advertise VIPs via BGP
		timer := time.NewTimer(config.Learn * time.Second)
		ticker := time.NewTicker(5 * time.Second)
		services := director.Status()

		defer func() {
			ticker.Stop()
			timer.Stop()
			pool.RIB(nil)
			time.Sleep(2 * time.Second)
			pool.Close()
		}()

		var initialised bool
		for {
			select {
			case <-ticker.C: // check for matured VIPs
			case <-director.C: // a backend has changed state
				services = director.Status()
			case <-done: // shuting down
				return
			case <-timer.C:
				logs.NOTICE(F, KV{"event": "Learn timer expired"})
				initialised = true
			}

			mutex.Lock()
			vip = vipState(services, vip, logs)
			rib = adjRIBOut(vip, initialised)
			mutex.Unlock()

			pool.RIB(rib)
		}
	}()

	fmt.Println("******************** RUNNING ********************")

	static := http.FS(STATIC)
	var fs http.FileSystem

	if *root != "" {
		fs = http.FileSystem(http.Dir(*root))
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if fs != nil {
			file := r.URL.Path
			if file == "/" {
				file = "/index.html"
			}

			if f, err := fs.Open(file); err == nil {
				f.Close()
				http.FileServer(fs).ServeHTTP(w, r)
				return
			}
		}

		r.URL.Path = "static/" + r.URL.Path
		http.FileServer(static).ServeHTTP(w, r)
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {

		start, _ := strconv.ParseUint(r.URL.Path[5:], 10, 64)
		logs := logs.get(index(start))
		js, err := json.MarshalIndent(&logs, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	// Remove this if migrating to a different load balancing engine
	http.HandleFunc("/prefixes.json", func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		p := client.Prefixes()
		fmt.Println(time.Now().Sub(t))
		js, _ := json.Marshal(&p)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	// Remove this if migrating to a different load balancing engine
	http.HandleFunc("/lb.json", func(w http.ResponseWriter, r *http.Request) {
		var ret []interface{}
		type status struct {
			Service      lb.ServiceExtended
			Destinations []lb.DestinationExtended
		}
		svcs, _ := client.Services()
		for _, se := range svcs {
			dsts, _ := client.Destinations(se.Service)
			ret = append(ret, status{Service: se, Destinations: dsts})
		}
		js, err := json.MarshalIndent(&ret, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		js, err := json.MarshalIndent(config, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/cue.json", func(w http.ResponseWriter, r *http.Request) {
		js, err := json.MarshalIndent(director.Status(), " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		js, err := json.MarshalIndent(struct {
			Summary  Summary               `json:"summary"`
			Services map[VIP][]Serv        `json:"services"`
			BGP      map[string]bgp.Status `json:"bgp"`
			VIP      []VIPStats            `json:"vip"`
			RIB      []netip.Addr          `json:"rib"`
		}{
			Summary:  summary,
			Services: services,
			BGP:      pool.Status(),
			VIP:      vipStatus(services, rib),
			RIB:      rib,
		}, " ", " ")
		mutex.Unlock()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {

		mutex.Lock()
		metrics := prometheus(services, summary, vip)
		mutex.Unlock()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Join(metrics, "\n") + "\n"))
	})

	go func() {
		log.Fatal(http.ListenAndServe(*webserver, nil))
	}()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGQUIT:
			logs.ALERT(F, "SIGQUIT received - shutting down")
			fmt.Println("CLOSING")
			close(done) // shut down BGP, etc
			time.Sleep(4 * time.Second)
			fmt.Println("DONE")
			return
		case syscall.SIGINT:
			logs.NOTICE(F, "Reload signal received")
			conf, err := Load(file)
			if err == nil {
				mutex.Lock()
				config = conf
				client.UpdateVLANs(config.vlans())
				director.Configure(config.parse())
				pool.Configure(config.BGP)
				mutex.Unlock()
			} else {
				logs.ALERT(F, "Couldn't load config file:", file, err)
			}
		}
	}
}

func serviceStatus(config *Config, client Client, director *cue.Director, old map[Key]Stats) (map[VIP][]Serv, map[Key]Stats, uint64) {

	var current uint64

	stats := map[Key]Stats{}
	status := map[VIP][]Serv{}

	for _, svc := range director.Status() {

		xs := lb.Service{Address: svc.Address, Port: svc.Port, Protocol: lb.Protocol(svc.Protocol)}
		xse, _ := client.Service(xs)

		t := Tuple{Addr: svc.Address, Port: svc.Port, Protocol: svc.Protocol}
		cnf, _ := config.Services[t]

		available := svc.Available()

		key := Key{VIP: svc.Address, Port: svc.Port, Protocol: svc.Protocol}
		serv := Serv{
			Name:        cnf.Name,
			Description: cnf.Description,
			Address:     svc.Address,
			Port:        svc.Port,
			Protocol:    protocol(svc.Protocol),
			Required:    svc.Required,
			Available:   available,
			Up:          svc.Up,
			For:         uint64(time.Now().Sub(svc.When) / time.Second),
			Stats:       old[key],
		}
		stats[key] = serv.Stats.update(xse.Stats)

		lbs := map[netip.Addr]lb.Stats{}
		mac := map[netip.Addr]string{}

		xd, _ := client.Destinations(xs)
		for _, d := range xd {
			lbs[d.Destination.Address] = d.Stats
			mac[d.Destination.Address] = d.MAC.String()
			current += d.Stats.Current
		}

		for _, dst := range svc.Destinations {
			status := dst.Status

			key := Key{
				VIP: svc.Address, Port: svc.Port, Protocol: svc.Protocol,
				RIP: dst.Address, RPort: dst.Port,
			}
			dest := Dest{
				Address:    dst.Address,
				Port:       dst.Port,
				Disabled:   dst.Disabled,
				Up:         status.OK,
				For:        uint64(time.Now().Sub(status.When) / time.Second),
				Took:       uint64(status.Took / time.Millisecond),
				Diagnostic: status.Diagnostic,
				Weight:     dst.Weight,
				MAC:        mac[dst.Address],
				Stats:      old[key],
			}
			stats[key] = dest.Stats.update(lbs[dst.Address])

			serv.Destinations = append(serv.Destinations, dest)
		}

		sort.SliceStable(serv.Destinations, func(i, j int) bool {
			return serv.Destinations[i].Address.Compare(serv.Destinations[j].Address) < 0
		})

		status[svc.Address] = append(status[svc.Address], serv)
	}

	return status, stats, current
}

func (s *Summary) summary(c Client) {
	u := c.Info()
	s.Latency = u.Latency
	s.Dropped = u.Dropped
	s.Blocked = u.Blocked
	s.NotQueued = u.NotQueued
	s.IngressOctets = u.Octets
	s.IngressPackets = u.Packets
	s.EgressOctets = 0  // Not available in DSR
	s.EgressPackets = 0 // Not available in DSR
	s.Flows = u.Flows

	s.DSR = true
	s.VC5 = true
}

func (s *Stats) update(u lb.Stats) Stats {
	o := *s

	s.IngressOctets = u.Octets
	s.IngressPackets = u.Packets
	s.EgressOctets = 0  // Not available in DSR
	s.EgressPackets = 0 // Not available in DSR
	s.Flows = u.Flows
	s.Current = u.Current
	s.time = time.Now()

	if o.time.Unix() != 0 {
		diff := uint64(s.time.Sub(o.time) / time.Millisecond)

		if diff != 0 {
			s.EgressPacketsPerSecond = (1000 * (s.EgressPackets - o.EgressPackets)) / diff
			s.EgressOctetsPerSecond = (1000 * (s.EgressOctets - o.EgressOctets)) / diff
			s.IngressPacketsPerSecond = (1000 * (s.IngressPackets - o.IngressPackets)) / diff
			s.IngressOctetsPerSecond = (1000 * (s.IngressOctets - o.IngressOctets)) / diff
			s.FlowsPerSecond = (1000 * (s.Flows - o.Flows)) / diff
		}
	}

	return *s
}
