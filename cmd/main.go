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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/bgp"
	"github.com/davidcoles/xvs"

	"vc5"
)

func main() {

	F := "vc5"

	var mutex sync.Mutex

	start := time.Now()
	webroot := flag.String("r", "", "webserver root directory")
	webserver := flag.String("w", ":80", "webserver listen address")
	sock := flag.String("s", "", "socket") // used internally
	addr := flag.String("a", "", "address")
	native := flag.Bool("n", false, "Native mode XDP")
	asn := flag.Uint("A", 0, "Autonomous system number to enable loopback BGP") // experimental - may change
	mp := flag.Bool("M", false, "Use multiprotocol extensions on loopback BGP") // experimental - may change
	delay := flag.Uint("D", 0, "Delay between initialisaton of interfaces")     // experimental - may change
	flows := flag.Uint("F", 0, "Set maximum number of flows")                   // experimental - may change
	cmd_path := flag.String("C", "", "Command channel path")                    // experimental - may change

	// Changing number of flows will only work on some kernels
	// Not supported: 5.4.0-171-generic
	// Supported: 5.15.0-112-generic, 6.6.28+rpt-rpi-v7

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

	config, err := vc5.Load(file)

	if err != nil {
		log.Fatal("Couldn't load config file:", config, err)
	}

	logs := &vc5.Sink{}
	logs.Start(config.Logging_())

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
		go bgpListener(l, logs.Sub("bgp"))
	}

	var cmd_sock net.Listener

	if *cmd_path != "" {
		os.Remove(*cmd_path)

		cmd_sock, err = net.Listen("unix", *cmd_path)

		if err != nil {
			log.Fatal(err)
		}
	}

	for _, i := range nics {
		ethtool(i)
	}

	client := &xvs.Client{
		Interfaces: nics,
		Address:    address,
		Native:     *native,
		VLANs:      config.Vlans(),
		InitDelay:  uint8(*delay),
		NAT:        true,
		Debug:      &Debug{Log: logs.Sub("xvs")},
		MaxFlows:   uint32(*flows),
	}

	err = client.Start()

	if err != nil {
		logs.EMERG(F, "Couldn't start client:", err)
		log.Fatal("Couldn't start client: ", err)
	}

	if cmd_sock != nil {
		go readCommands(cmd_sock, client, logs.Sub("command"))
	}

	routerID := address.As4()

	if *asn > 0 {
		routerID = [4]byte{127, 0, 0, 1}
	}

	pool := bgp.NewPool(routerID, config.Bgp(uint16(*asn), *mp), nil, logs.Sub("bgp"))

	if pool == nil {
		log.Fatal("BGP pool fail")
	}

	go spawn(logs, client.Namespace(), os.Args[0], "-s", socket.Name(), client.NamespaceAddress())

	balancer := &Balancer{
		NetNS:  NetNS(socket.Name()),
		Logger: logs.Sub("balancer"),
		Client: client,
	}

	director := &cue.Director{
		Notifier: balancer,
		Prober:   balancer,
	}

	if config.Multicast != "" {
		multicast(client, config.Multicast)
	}

	err = director.Start(config.Parse())

	if err != nil {
		logs.EMERG(F, "Couldn't start director:", err)
		log.Fatal(err)
	}

	done := make(chan bool) // close this channel when we want to exit

	vip := map[netip.Addr]vc5.State{}

	var rib []netip.Addr
	var summary vc5.Summary

	services, old, _ := vc5.ServiceStatus(config, balancer, director, nil)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			mutex.Lock()
			summary.Update(balancer.summary(), start)
			services, old, summary.Current = vc5.ServiceStatus(config, balancer, director, old)
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
				mutex.Lock()
				services = director.Status()
				balancer.configure(services)
				mutex.Unlock()
			case <-done: // shuting down
				return
			case <-timer.C:
				logs.NOTICE(F, KV{"event": "Learn timer expired"})
				initialised = true
			}

			mutex.Lock()
			vip = vc5.VipState(services, vip, config.Priorities(), logs)
			rib = vc5.AdjRIBOut(vip, initialised)
			mutex.Unlock()

			pool.RIB(rib)
		}
	}()

	static := http.FS(vc5.STATIC)
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
		logs := logs.Get(start)
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
		//config.Untagged = *untagged
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
		js, err := vc5.JSONStatus(summary, services, vip, pool, rib, logs.Stats())
		/*
			js, err := json.MarshalIndent(struct {
				Summary  vc5.Summary           `json:"summary"`
				Services vc5.Services          `json:"services"`
				BGP      map[string]bgp.Status `json:"bgp"`
				VIP      []vc5.VIPStats        `json:"vip"`
				RIB      []netip.Addr          `json:"rib"`
				Logging  vc5.LogStats          `json:"logging"`
			}{
				Summary:  summary,
				Services: services,
				BGP:      pool.Status(),
				VIP:      vc5.VipStatus(services, vip),
				RIB:      rib,
				Logging:  logs.Stats(),
			}, " ", " ")
		*/
		mutex.Unlock()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		js = append(js, 0x0a) // add a newline
		w.Write(js)
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {

		mutex.Lock()
		metrics := vc5.Prometheus("vc5", services, summary, vip)
		mutex.Unlock()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Join(metrics, "\n") + "\n"))
	})

	go func() {
		for {
			server := http.Server{}
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
			conf, err := vc5.Load(file)
			if err == nil {
				mutex.Lock()
				config = conf
				client.UpdateVLANs(config.Vlans())
				director.Configure(config.Parse())
				pool.Configure(config.Bgp(uint16(*asn), *mp))
				logs.Configure(conf.Logging_())
				mutex.Unlock()
			} else {
				logs.ALERT(F, "Couldn't load config file:", file, err)
			}

		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			fmt.Println("CLOSING")
			close(done) // shut down BGP, etc
			logs.ALERT(F, "Shutting down")
			time.Sleep(4 * time.Second)
			return
		}
	}
}

func bgpListener(l net.Listener, logs vc5.Logger) {
	F := "listener"

	for {
		conn, err := l.Accept()

		if err != nil {
			logs.ERR(F, "Failed to accept connection", err)
		} else {
			go func(c net.Conn) {
				logs.INFO(F, "Accepted connection from", conn.RemoteAddr())
				defer c.Close()
				time.Sleep(time.Second * 10)
			}(conn)
		}
	}
}
