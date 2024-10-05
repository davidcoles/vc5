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
	addr := flag.String("a", "", "address")
	native := flag.Bool("n", false, "Native mode XDP")
	socket := flag.String("s", "/var/run/vc5", "socket")
	proxy := flag.String("P", "", "run as healthcheck proxy server")            // used internally
	asn := flag.Uint("A", 0, "Autonomous system number to enable loopback BGP") // experimental - may change
	bgp := flag.Bool("b", false, "Disable BGP listener on port 179")            // experimental - may change
	delay := flag.Uint("D", 0, "Delay between initialisaton of interfaces")     // experimental - may change
	flows := flag.Uint("F", 0, "Set maximum number of flows")                   // experimental - may change
	cmd_path := flag.String("C", "", "Command channel path")                    // experimental - may change
	hardfail := flag.Bool("H", false, "Hard fail on configuration apply")       // experimental - may change

	// Changing number of flows will only work on newer kernels
	// Not supported: 5.4.0-171-generic
	// Supported: 5.15.0-112-generic, 6.6.28+rpt-rpi-v7

	flag.Parse()

	args := flag.Args()

	if *proxy != "" {
		// we're going to be the server running in the network namespace ...
		signal.Ignore(syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		netns(*proxy, netip.MustParseAddr(args[0]))
		return
	}

	file := args[0]
	nics := args[1:]

	config, err := vc5.Load(file)

	if err != nil {
		log.Fatal("Couldn't load config file:", config, err)
	}

	logs := vc5.NewLogger(*addr, config.LoggingConfig())

	if len(nics) < 1 {
		logs.Fatal(F, "args", KV{"error.message": "No interfaces defined"})
	}

	address := netip.MustParseAddr(*addr)

	if !address.Is4() {
		logs.Fatal(F, "args", KV{"error.message": "Address is not IPv4: " + address.String()})
	}

	routerID := address.As4()

	var webListener net.Listener

	// Before making any changes to the state of the system (loading
	// XDP, etc) we attempt to listen on the webserver port. This
	// should prevent multiple instances running at the same time and
	// interfering with each other.
	if *webserver != "" {
		webListener, err = net.Listen("tcp", *webserver)
		if err != nil {
			log.Fatal(err)
		}
	}

	// If BGP peers do not support a "passive" option (eg. ExtremeXOS)
	// then we may need to listen on port 179 to prevent the session
	// getting into an error state - the manager will accept the
	// connection but then quietly drop it after ten seconds or
	// so. This seems to keep the peer happy.
	//err = bgpListener(logs.Sub("bgp"))
	if !*bgp {
		err = bgpListener(logs)
		if err != nil {
			log.Fatal(err)
		}
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

	// Short delay to let interfaces quiesce after loading XDP
	time.Sleep(5 * time.Second)

	// Create a balancer instance - this implements interface methods
	// (configuration changes, stats requests, etc). which are called
	// by the manager object (which handles the main event loop)
	balancer := &Balancer{
		Client: client,
		Logger: logs.Sub("balancer"),
	}

	// Run server to perform healthchecks in network namespace, handle
	// commands from UNIX socket and share flow info via multicast
	balancer.start(*socket, cmd_sock, config.Multicast)

	// Add some custom HTTP endpoints to the default mux to handle
	// requests specific to this type of load balancer client
	httpEndpoints(client, logs)

	// context to use for shutting down services when we're about to exit
	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	// The manager handles the main event loop, healthchecks, requests
	// for the console/metrics, sets up BGP sessions, etc.
	manager := vc5.Manager{
		Balancer:    balancer,
		Logs:        logs,
		NAT:         nat(client),             // We use a NAT method and a custom probe function
		Prober:      prober(client, *socket), // to run checks from the inside network namespace
		RouterID:    routerID,                // BGP router ID to use to speak to peers
		WebRoot:     *webroot,                // Serve static files from this directory
		WebListener: webListener,             // Listen for incoming web connections if not nil
		BGPLoopback: uint16(*asn),            // If non-zero then loopback BGP is activated
		Interval:    2,                       // Delay in seconds between updating statistics
		HardFail:    *hardfail,               // Exit if apply (not load) of config fails, when set
	}

	//if err := manager.Manage(ctx, listener); err != nil {
	if err := manager.Manage(ctx, config); err != nil {
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
				client.UpdateVLANs(conf.Vlans())
				manager.Configure(conf)
			} else {
				text := "Couldn't load config file " + file + " :" + err.Error()
				logs.Alert(vc5.ALERT, F, "config", KV{"file.path": file, "error.message": err.Error()}, text)
			}

		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			logs.Alert(vc5.ALERT, F, "exiting", KV{}, "Exiting")
			return
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

func bgpListener(logs vc5.Logger) error {
	F := "bgp.listener"

	l, err := net.Listen("tcp", ":179")

	if err == nil {
		go func() {
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
		}()
	}

	return err
}
