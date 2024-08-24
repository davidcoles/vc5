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
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/davidcoles/xvs"

	"vc5"
)

func main() {

	F := "vc5"

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

	logs := vc5.NewLogger(config.HostID, config.LoggingConfig())

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

	routerID := address.As4()

	// Before making any changes to the state of the system (loading
	// XDP, etc) we attempt to listen on the webserver port. This
	// should prevent multiple instances running at the same time and
	// interfering with each other.
	var listener net.Listener
	if *webserver != "" {
		listener, err = net.Listen("tcp", *webserver)
		if err != nil {
			log.Fatal(err)
		}
	}

	// If BGP peers do not support a "passive" option (eg. ExtremeXOS)
	// then we may need to listen on port 179 to prevent the session
	// getting into a error state - we accept the connection but then
	// quietly drop it after ten seconds or so. This seems to keep the
	// device happy.
	if config.Listen {
		l, err := net.Listen("tcp", ":179")
		if err != nil {
			log.Fatal("Couldn't listen on BGP port", err)
		}
		go bgpListener(l, logs.Sub("bgp"))
	}

	// Open a UNIX domain socket for receiving commands whilst
	// running. Currently used to re-attach XDP code to an interface
	// as a mitigation for some badly behaved network cards.
	var cmd_sock net.Listener
	if *cmd_path != "" {
		os.Remove(*cmd_path)
		if cmd_sock, err = net.Listen("unix", *cmd_path); err != nil {
			log.Fatal(err)
		}
	}

	// Run ethtool against the network interfaces to disable various
	// offload parameters which seem to interfere with XDP operations
	ethtool(nics)

	// Initialise the load balancing library which will deal with the
	// data-plane - this is what actually switches incoming packets
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

	if err = client.Start(); err != nil {
		logs.Fatal(F, "client", KV{"error.message": "Couldn't start client: " + err.Error()})
	}

	// Create a balancer instance  - this implements interface methods
	// (configuration changes, stats  requests, etc). which are called
	// by the manager object (which handles the main event loop)
	balancer := &Balancer{
		NetNS:  NetNS(socket.Name()),
		Logger: logs.Sub("balancer"),
		Client: client,
	}

	// Run server to perform healthchecks in network namespace, handle
	// commands from UNIX socket and share flow info via multicast
	balancer.start(socket, cmd_sock, config.Multicast)

	// Add some custom HTTP endpoints to the default mux to handle
	// requests specific to this type of load balancer client (xvs)
	httpEndpoints(client, logs)

	ctx, shutdown := context.WithCancel(context.Background())

	manager := vc5.Manager{
		Config:   config,
		Balancer: balancer,
		Logs:     logs,
		NAT:      balancer.nat(),    // We use a NAT method and a custom probe function
		Prober:   balancer.prober(), // to run checks from the network namespace
		RouterID: routerID,          // BGP router ID to use to speak to peers
		ASNumber: uint16(*asn),      // If non-zero then loopback BGP is activated
		IPv4Only: !(*mp),            // By default we send multiprotocol BGP capabilites (for IPv6)
	}

	if err := manager.Manage(ctx, listener); err != nil {
		logs.Fatal(F, "manager", KV{"error.message": "Couldn't start manager: " + err.Error()})
	}

	// We are succesfully up and running, so send a high priority
	// alert to let the world know - perhaps we crashed previously and
	// were restarted by the service manager
	logs.Alert(vc5.ALERT, F, "initialised", KV{}, "Initialised")

	// We now wait for signals to tell us to reload the configuration file or exit
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
				config = conf
				config.Address = *addr
				config.Interfaces = nics
				config.Native = *native
				config.Webserver = *webserver
				config.Webroot = *webroot
				client.UpdateVLANs(conf.Vlans())
				manager.Configure(conf)
			} else {
				text := "Couldn't load config file " + file + " :" + err.Error()
				logs.Alert(vc5.ALERT, F, "config", KV{"file.path": file, "error.message": err.Error()}, text)
			}

		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			shutdown() // cancel context to shut down BGP, etc
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

func httpEndpoints(client Client, logs vc5.Logger) {

	http.HandleFunc("/prefixes.json", func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		p := client.Prefixes()
		milliseconds := time.Now().Sub(t) / time.Millisecond
		logs.Event(6, "web", "prefixes", KV{"milliseconds": milliseconds})
		js, err := json.Marshal(&p)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		js = append(js, 0x0a) // add a newline for readability
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	})

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
		js = append(js, 0x0a) // add a newline for readability
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	})
}
