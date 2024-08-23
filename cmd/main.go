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
	//"runtime/debug"
	//"strconv"
	//"strings"
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/xvs"

	"vc5"
)

func main() {

	F := "vc5"

	var mutex sync.Mutex

	//start := time.Now()
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
		logs.Fatal(F, "socket", KV{"error.message": err.Error()})
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
		logs.Fatal(F, "args", KV{"error.message": "No interfaces defined"})
	}

	address := netip.MustParseAddr(*addr)

	if !address.Is4() {
		logs.Fatal(F, "args", KV{"error.message": "Address is not IPv4: " + address.String()})
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
		logs.Fatal(F, "client", KV{"error.message": "Couldn't start client: " + err.Error()})
	}

	if cmd_sock != nil {
		go readCommands(cmd_sock, client, logs.Sub("xvs"))
	}

	routerID := address.As4()

	if *asn > 0 {
		routerID = [4]byte{127, 0, 0, 1}
	}

	go spawn(logs, client.Namespace(), os.Args[0], "-s", socket.Name(), client.NamespaceAddress())

	balancer := &Balancer{
		NetNS:  NetNS(socket.Name()),
		Logger: logs.Sub("balancer"),
		Client: client,
	}

	if config.Multicast != "" {
		multicast(client, config.Multicast)
	}

	done := make(chan bool) // close this channel when we want to exit

	nat := func(vip, rip netip.Addr) netip.Addr {
		nat, _ := client.NATAddress(vip, rip)
		return nat
	}

	prober := func(i vc5.Instance, check vc5.Check) (ok bool, diagnostic string) {
		vip := i.Service.Address
		rip := i.Destination.Address
		nat, ok := client.NATAddress(vip, rip)

		if !ok {
			diagnostic = "No NAT destination defined for " + vip.String() + "/" + rip.String()
		} else {
			ok, diagnostic = balancer.NetNS.Probe(nat, check)
		}

		return ok, diagnostic
	}

	manager := vc5.Manager{
		Config:   config,
		Balancer: balancer,
		Logs:     logs,
		Prober:   prober,
		NAT:      nat,
	}

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

	if err := manager.Manage(listener, routerID, uint16(*asn), *mp, done); err != nil {
		logs.Fatal(F, "manager", KV{"error.message": "Couldn't start manager: " + err.Error()})
	}

	logs.Alert(vc5.ALERT, F, "initialised", KV{}, "Initialised")

	sig := make(chan os.Signal, 10)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGUSR2:
			logs.Alert(vc5.NOTICE, F, "reload", KV{}, "Reload signal received")
			conf, err := vc5.Load(file)
			if err == nil {
				mutex.Lock()
				config = conf

				config.Address = *addr
				config.Interfaces = nics
				config.Native = *native
				config.Webserver = *webserver
				config.Webroot = *webroot
				client.UpdateVLANs(conf.Vlans())
				manager.Configure(conf)
				mutex.Unlock()
			} else {
				logs.Alert(vc5.ALERT, F, "config", KV{"error.message": fmt.Sprint("Couldn't load config file:", file, err)})
			}

		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			close(done) // shut down BGP, etc
			logs.Alert(vc5.ALERT, F, "exiting", KV{}, "Exiting")
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
			logs.Event(vc5.ERR, F, "accept", KV{"error.message": err.Error()})
		} else {
			go func(c net.Conn) {
				logs.Event(vc5.INFO, F, "accept", KV{"client.address": conn.RemoteAddr().String()})
				defer c.Close()
				time.Sleep(time.Second * 10)
			}(conn)
		}
	}
}
