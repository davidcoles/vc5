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
	"fmt"
	"log"
	"log/slog"
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

type leveler struct {
}

func (l *leveler) Level() slog.Level { return slog.LevelDebug }

func main() {

	const FACILITY = "vc5"

	// XVS specific
	learn := flag.Uint("l", 0, "Learn; wait for this many seconds before advertising VIPs (for multicast flow state adverts)")
	native := flag.Bool("n", false, "Use native mode XDP; better performance on network cards that support it")
	multicast := flag.String("m", "", "Multicast address used to share flow state between instances")
	flows := flag.Uint("F", 0, "Set maximum number of flows (per-core)")
	delay := flag.Uint("D", 0, "Delay between initialisaton of interfaces (to prevent bond from flapping)")
	//cmd_path := flag.String("C", "", "Command channel path")

	// common with stayinalived
	listen := flag.Bool("b", false, "Enable BGP listener on port 179")
	webroot := flag.String("r", "", "Webserver root directory to override built-in documents")
	webserver := flag.String("w", ":80", "Webserver listen address")
	asn := flag.Uint("A", 0, "Autonomous System Number to enable loopback BGP")
	hardfail := flag.Bool("H", false, "Hard fail on balancer configuration error")
	closeidle := flag.Bool("c", false, "Close idle HTTP connections")
	hostid := flag.String("I", "", "Host ID for logging")

	flag.Bool("toobig", false, "dummy")

	timeout := flag.Uint("timeout", 0, "Timeout program after this many minutes - fail safe for testing")
	test := flag.Bool("test", false, "test mode - debug logging")

	// Changing number of flows will only work on newer kernels
	// Not supported: 5.4.0-171-generic
	// Supported: 5.15.0-112-generic, 6.6.28+rpt-rpi-v7

	flag.Parse()

	args := flag.Args()

	/*
		tunnel := xvs.NONE

		switch *tunnelType {
		case "none":
			tunnel = xvs.NONE
		case "ipip":
			tunnel = xvs.IPIP
		case "gre":
			tunnel = xvs.GRE
		case "fou":
			tunnel = xvs.FOU
		case "gue":
			tunnel = xvs.GUE
		default:
			log.Fatal("Unsupported tunnel type: ", *tunnelType)
		}
	*/

	addr := args[0]
	file := args[1]
	nics := args[2:]

	config, err := vc5.Load(file)

	if err != nil {
		log.Fatal("Couldn't load config file:", config, err)
	}

	if *hostid == "" {
		*hostid = addr
	}

	//logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: &leveler{}}))
	//logger := slog.Default()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &leveler{}}))

	if !*test {
		logger = nil
	}

	logs := vc5.NewLogger(*hostid, config.LoggingConfig())

	if len(nics) < 1 {
		logs.Fatal(FACILITY, "args", KV{"error.message": "No interfaces defined"})
	}

	address, err := netip.ParseAddr(addr)

	if err != nil {
		logs.Fatal(FACILITY, "args", KV{"error.message": "Invalid address"})
	}

	if !address.Is4() {
		logs.Fatal(FACILITY, "args", KV{"error.message": "Address is not IPv4: " + address.String()})
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
	if *listen {
		err = bgpListener(logs)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Open a UNIX domain socket for receiving commands whilst
	// running. Currently used to re-attach XDP code to an interface
	// as a mitigation for some badly behaved network cards.
	//	var cmd_sock net.Listener
	//if *cmd_path != "" {
	//	os.Remove(*cmd_path)
	//	if cmd_sock, err = net.Listen("unix", *cmd_path); err != nil {
	//		log.Fatal(err)
	//	}
	//}

	// Run ethtool against the network interfaces to disable various
	// offload parameters which seem to interfere with XDP operations
	ethtool(nics)

	// Initialise the load balancing library which will deal with the
	// data-plane - this is what actually switches incoming packets

	opts := xvs.Options{
		IPv4VLANs:          config.Prefixes(),
		IPv6VLANs:          config.Prefixes6(),
		DriverMode:         *native,
		FlowsPerCPU:        uint32(*flows),
		InterfaceInitDelay: uint8(*delay),
		Logger:             logger,
		Bonding:            false,
	}

	client, err := xvs.NewWithOptions(opts, nics...)

	if err != nil {
		logs.Fatal(FACILITY, "client", KV{"error.message": "Couldn't start client: " + err.Error()})
	}

	info, err := client.Info()

	if err != nil {
		logs.Fatal(FACILITY, "client", KV{"error.message": "Couldn't get client info: " + err.Error()})
	}

	inside := info.IPv4
	monitor, err := vc5.Monitor(inside, false)

	if *timeout > 0 {
		go func() {
			time.Sleep(time.Minute * time.Duration(*timeout))
			log.Fatal("timeout")
		}()
	}

	// Short delay to let interfaces quiesce after loading XDP
	//time.Sleep(5 * time.Second)

	// Add a short delay on return to allow BGP, etc to cleanly exit
	defer time.Sleep(5 * time.Second)

	// Create a balancer instance - this implements interface methods
	// (configuration changes, stats requests, etc). which are called
	// by the manager object (which handles the main event loop)
	balancer := &Balancer{
		Client: client,
		Logger: logs.Sub("balancer"),
		//tunnel: tunnel,
		//port:   uint16(*tunnelPort),
	}

	// Run services to perform healthchecks in network namespace, handle
	// commands from UNIX socket and share flow info via multicast
	//services(os.Args[0], *closeidle, client, *socket, cmd_sock, *multicast, balancer.Logger)
	services(os.Args[0], *closeidle, client, *multicast, balancer.Logger)

	// Add some custom HTTP endpoints to the default mux to handle
	// requests specific to this type of load balancer client
	httpEndpoints(client, balancer, logs)

	// context to use for shutting down services when we're about to exit
	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	// The manager handles the main event loop, healthchecks, requests
	// for the console/metrics, sets up BGP sessions, etc.
	manager := vc5.Manager{
		Balancer:    balancer,
		Logs:        logs,
		Learn:       *learn,                  // Number of seconds to wait before advertising any VIPs
		NAT:         nat(client),             // We use a NAT method and a custom probe function
		Prober:      prober(client, monitor), // to run checks from the inside network namespace
		RouterID:    routerID,                // BGP router ID to use to speak to peers
		WebRoot:     *webroot,                // Serve static files from this directory
		WebListener: webListener,             // Listen for incoming web connections if not nil
		BGPLoopback: uint16(*asn),            // If non-zero then loopback BGP is enabled
		Interval:    2,                       // Delay in seconds between updating statistics
		HardFail:    *hardfail,               // Exit if apply (not load) of config fails, when set
	}

	if err := manager.Manage(ctx, config); err != nil {
		logs.Fatal(FACILITY, "manager", KV{"error.message": "Couldn't start manager: " + err.Error()})
	}

	// We are succesfully up and running, so send a high priority
	// alert to let the world know - perhaps we crashed previously and
	// were restarted by the service manager
	logs.Alert(vc5.ALERT, FACILITY, "initialised", KV{}, "Initialised")

	// We now wait for signals to tell us to reload the configuration file or exit
	sig := make(chan os.Signal, 10)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		switch <-sig {
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGUSR2:
			logs.Alert(vc5.NOTICE, FACILITY, "reload", KV{}, "Reload signal received")
			conf, err := vc5.Load(file)
			if err == nil {
				config = conf
				c := xvs.Config{IPv4VLANs: config.Prefixes(), IPv6VLANs: config.Prefixes6()}
				err := client.SetConfig(c)
				log.Println(err)
				manager.Configure(conf)
			} else {
				text := "Couldn't load config file " + file + " :" + err.Error()
				logs.Alert(vc5.ALERT, FACILITY, "config", KV{"file.path": file, "error.message": err.Error()}, text)
			}

		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			logs.Alert(vc5.ALERT, FACILITY, "exiting", KV{}, "Exiting")
			return
		}
	}
}

func httpEndpoints(client Client, balancer *Balancer, logs vc5.Logger) {

	/*
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
	*/

	http.HandleFunc("/xxmetrics", func(w http.ResponseWriter, r *http.Request) {
		names, metrics := balancer.Metrics()
		w.Header().Set("Content-Type", "text/plain")

		for _, n := range names {
			w.Write([]byte(fmt.Sprintf("# TYPE xvs_%s counter\n", n)))
		}

		for _, m := range metrics {
			w.Write([]byte(fmt.Sprintln("xvs_" + m)))
		}
	})

	http.HandleFunc("/lb.json", func(w http.ResponseWriter, r *http.Request) {
		var ret []interface{}
		type status struct {
			Service      ServiceExtended
			Destinations []DestinationExtended
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
						defer c.Close()
						logs.Event(vc5.INFO, F, "accept", KV{"client.address": conn.RemoteAddr().String()})
						time.Sleep(time.Second * 10)
					}(conn)
				}
			}
		}()
	}

	return err
}

// func services(binary string, closeidle bool, client Client, socket string, cmd_sock net.Listener, multicast string, logger vc5.Logger) {
func services(binary string, closeidle bool, client Client, multicast string, logger vc5.Logger) {
	/*
		cmd := []string{binary}

		if closeidle {
			cmd = append(cmd, "-I")
		}

		cmd = append(cmd, "-P", socket, client.NamespaceAddress())

		go spawn(logger, client.Namespace(), cmd...)
	*/

	//go readCommands(cmd_sock, client, logger)

	if multicast != "" {
		go multicast_send(client, multicast)
		go multicast_recv(client, multicast)
	}
}
