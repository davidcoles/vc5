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
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	//"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/bgp"
	"github.com/davidcoles/xvs"
)

// TODO:

//go:embed static/*
var STATIC embed.FS

func main() {

	F := "vc5"

	var mutex sync.Mutex

	start := time.Now()
	webroot := flag.String("r", "", "webserver root directory")
	webserver := flag.String("w", ":80", "webserver listen address")
	sock := flag.String("s", "", "socket") // used internally
	addr := flag.String("a", "", "address")
	native := flag.Bool("n", false, "Native mode XDP")
	untagged := flag.Bool("u", false, "Untagged VLAN mode")

	flag.Parse()

	args := flag.Args()

	if *sock != "" {
		// we're going to be the server running in the network namespace ...
		signal.Ignore(syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		netns(*sock, netip.MustParseAddr(args[0]))
		return
	}

	file := args[0]
	nics := args[1:]

	config, err := Load(file)

	if err != nil {
		log.Fatal("Couldn't load config file:", config, err)
	}

	logs := &(config.Logging)

	socket, err := ioutil.TempFile("/tmp", "vc5ns")

	if err != nil {
		logs.EMERG(F, "socket", err)
		log.Fatal(err)
	}

	defer os.Remove(socket.Name())

	if config.Address != "" {
		*addr = config.Address
	}

	if len(config.Interfaces) > 0 {
		nics = config.Interfaces
	}

	if config.Native {
		*native = true
	}

	if config.Untagged {
		*untagged = true
	}

	if config.Webserver != "" {
		*webserver = config.Webserver
	}

	if config.Webroot != "" {
		*webroot = config.Webroot
	}

	if len(nics) < 1 {
		logs.EMERG(F, "No interfaces defined")
		log.Fatal("No interfaces defined")
	}

	address := netip.MustParseAddr(*addr)

	if !address.Is4() {
		logs.EMERG(F, "Address is not IPv4:", address)
		log.Fatal("Address is not IPv4: ", address)
	}

	var listener net.Listener

	if *webserver != "" {
		listener, err = net.Listen("tcp", *webserver)
		if err != nil {
			log.Fatal(err)
		}
	}

	if config.Listen {
		l, err := net.Listen("tcp", ":179")
		if err != nil {
			log.Fatal("Couldn't listen on BGP port", err)
		}
		go bgpListener(l, logs.sub("bgp"))
	}

	for _, i := range nics {
		ethtool(i)
	}

	client := &xvs.Client{
		Interfaces: nics,
		Address:    address,
		Redirect:   *untagged,
		Native:     *native,
		VLANs:      config.vlans(),
		NAT:        true,
		Logger:     logs.sub("xvs"),
		Share:      config.Multicast != "",
		//Debug:      &Debug{Log: logs.sub("test")},
	}

	err = client.Start()

	if err != nil {
		logs.EMERG(F, "Couldn't start client:", err)
		log.Fatal(err)
	}

	pool := bgp.NewPool(address.As4(), config.BGP, nil, logs.sub("bgp"))

	if pool == nil {
		log.Fatal("BGP pool fail")
	}

	go spawn(logs, client.Namespace(), os.Args[0], "-s", socket.Name(), client.NamespaceAddress())

	balancer := &Balancer{
		NetNS:  NetNS(socket.Name()),
		Logger: logs,
		Client: client,
	}

	director := &cue.Director{
		Balancer: balancer,
	}

	if config.Multicast != "" {
		balancer.Multicast(config.Multicast)
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

	services, old, _ := serviceStatus(config, balancer, director, nil)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			mutex.Lock()
			//summary.update(client, uint64(time.Now().Sub(start)/time.Second))

			summary.update(balancer.summary(), start)

			services, old, summary.Current = serviceStatus(config, balancer, director, old)
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

	static := http.FS(STATIC)
	var fs http.FileSystem

	if *webroot != "" {
		fs = http.FileSystem(http.Dir(*webroot))
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

	http.HandleFunc("/build.json", func(w http.ResponseWriter, r *http.Request) {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		js, err := json.MarshalIndent(info, " ", " ")
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
			Service      xvs.ServiceExtended
			Destinations []xvs.DestinationExtended
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

		config.Address = *addr
		config.Interfaces = nics
		config.Native = *native
		config.Untagged = *untagged
		config.Webserver = *webserver
		config.Webroot = *webroot

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
			Logging  LogStats              `json:"logging"`
		}{
			Summary:  summary,
			Services: services,
			BGP:      pool.Status(),
			VIP:      vipStatus(services, vip),
			RIB:      rib,
			Logging:  logs.Stats(),
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
		metrics := prometheus("vc5", services, summary, vip)
		mutex.Unlock()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Join(metrics, "\n") + "\n"))
	})

	go func() {
		for {
			server := http.Server{}
			//log.Fatal(server.Serve(listener))
			err := server.Serve(listener)
			logs.ALERT(F, "Webserver exited: "+err.Error())
			time.Sleep(10 * time.Second)
		}
	}()

	logs.ALERT(F, "Initialised")

	sig := make(chan os.Signal, 10)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGUSR2:
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

		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			fmt.Println("CLOSING")
			close(done) // shut down BGP, etc
			time.Sleep(4 * time.Second)
			logs.ALERT(F, "Shutting down")
			return
		}
	}
}

func mac(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

type Debug struct{ Log *sub }

var foo atomic.Uint64

func (d *Debug) NAT(tag map[netip.Addr]int16, arp map[netip.Addr][6]byte, vrn map[[2]netip.Addr]netip.Addr, nat map[netip.Addr]string, out []netip.Addr, in []string) {

	f := foo.Add(1)

	//fmt.Println("NAT")
	d.Log.INFO("nat", KV{"run": f})
	for k, v := range tag {
		fmt.Printf("TAG %s -> %d\n", k, v)
		d.Log.INFO("tag", KV{"run": f, "rip": k, "tag": v})

	}

	for k, v := range arp {
		fmt.Printf("ARP %s -> %v\n", k, mac(v))
		d.Log.INFO("arp", KV{"run": f, "rip": k, "mac": mac(v)})
	}

	for k, v := range vrn {
		fmt.Printf("MAP %s|%s -> %s\n", k[0], k[1], v)
		d.Log.INFO("map", KV{"run": f, "vip": k[0], "rip": k[1], "nat": v})
	}

	for k, v := range nat {
		fmt.Printf("NAT %s -> %s\n", k, v)
		d.Log.INFO("nat", KV{"run": f, "nat": k, "info": v})
	}

	for _, v := range out {
		fmt.Println("DEL nat_out", v)
		d.Log.INFO("delete", KV{"run": f, "out": v})
	}

	for _, v := range in {
		fmt.Println("DEL nat_in", v)
		d.Log.INFO("delete", KV{"run": f, "in": v})
	}
}

func (d *Debug) Redirects(vlans map[uint16]string) {
	fmt.Println("REDIRECTS")
	f := foo.Add(1)
	for k, v := range vlans {
		fmt.Println("NIC", k, v)
		d.Log.INFO("nic", KV{"run": f, "vlan": k, "info": v})
	}
}

func (d *Debug) Backend(vip netip.Addr, port uint16, protocol uint8, backends []byte, took time.Duration) {
	fmt.Println(vip, port, protocol, backends, took)
	d.Log.INFO("backend", KV{"vip": vip, "port": port, "protocol": protocol, "backends": fmt.Sprint(backends), "took": took.String()})
}
