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
	"encoding/base64"
	"encoding/json"
	//"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
	"github.com/davidcoles/vc5/bgp"
)

var logger *Logger

//go:embed static/*
var STATIC embed.FS

type IP4 = vc5.IP4
type L4 = vc5.L4
type Target = vc5.Target
type Balancer = vc5.Balancer

var level = flag.Uint("l", LOG_ERR, "debug level level")
var kill = flag.Uint("k", 0, "killswitch engage - automatic shutoff after k minutes")
var dfcn = flag.Uint("d", 5, "defcon readiness level")
var auth = flag.String("a", "", "user auth")
var sock = flag.String("s", "", "unix domain socket to use when spawning healthcheck server")
var bond = flag.String("i", "", "name of egress interface to use (eg. bond0)")
var root = flag.String("r", "", "webserver root directory")
var websrv = flag.String("w", ":9999", "webserver address:port to listen on")
var native = flag.Bool("n", false, "load xdp program in native mode")
var multi = flag.Bool("m", false, "multi-nic mode")
var nolabel = flag.Bool("N", false, "don't add 'name' label to prometheus metrics")

const RLIMIT_MEMLOCK = 8
const PREFIXES = 1048576

func ulimit(resource int) {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(resource, &rLimit); err != nil {
		log.Fatal("Error Getting Rlimit ", err)
	}
	rLimit.Max = 0xffffffffffffffff
	rLimit.Cur = 0xffffffffffffffff
	if err := syscall.Setrlimit(resource, &rLimit); err != nil {
		log.Fatal("Error Setting Rlimit ", err)
	}
}

func main() {

	var rib []IP

	flag.Parse()
	args := flag.Args()

	if *sock != "" {
		signal.Ignore(syscall.SIGUSR2, syscall.SIGQUIT)
		vc5.NetnsServer(*sock)
		return
	}

	ulimit(RLIMIT_MEMLOCK)

	file := args[0]
	addr := args[1]
	peth := args[2:]

	conf, err := vc5.LoadConf(file)

	if err != nil {
		log.Fatal(err)
	}

	if false {
		j, _ := json.MarshalIndent(conf, "", "  ")
		fmt.Println(string(j))
		return
	}

	if conf.Webserver != "" {
		*websrv = conf.Webserver
	}

	s, err := net.Listen("tcp", *websrv)

	if err != nil {
		log.Fatal(err)
	}

	temp, err := ioutil.TempFile("/tmp", "prefix")
	if err != nil {
		log.Fatal(err)
	}
	socket := temp.Name()
	defer os.Remove(socket)

	for _, v := range peth {
		exec.Command("/bin/sh", "-c", "ethtool -K "+v+" tx off; ethtool -K "+v+" rxvlan off;").Output()
		exec.Command("/bin/sh", "-c", "ethtool -K "+v+" rx off; ethtool -K "+v+" txvlan off;").Output()
	}

	hc, err := vc5.Load(conf)

	if err != nil {
		log.Fatal(err)
	}

	if false {
		j, _ := json.MarshalIndent(hc, "", "  ")
		fmt.Println(string(j))
		return
	}

	logger = &Logger{Level: uint8(*level)}

	pool := bgp.NewPool(addr, conf.RHI, nil)

	if pool == nil {
		log.Fatal("pool fail")
	}

	balancer := &vc5.VC5{
		ReadinessLevel:  uint8(*dfcn),
		Native:          *native,
		MultiNIC:        *multi,
		Socket:          socket,
		NetnsCommand:    []string{os.Args[0], "-s", socket},
		Interfaces:      peth,
		EgressInterface: *bond,
		Logger:          logger,
		Distributed:     conf.Multicast != "",
	}

	director := &vc5.Director{
		Balancer: balancer,
		Logger:   logger,
	}

	err = director.Start(addr, hc)

	if err != nil {
		log.Fatal(err)
	}

	if *kill > 0 {
		// auto kill switch
		go func() {
			for {
				time.Sleep(time.Duration(*kill) * time.Minute)
				logger.ALERT("LoadBalancer", "DISABLING")
				balancer.DEFCON(0)
			}
		}()
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGUSR2, syscall.SIGQUIT)
	//signal.Notify(sig) // all the signals!

	go func() {
		for {
			s := <-sig
			switch s {
			case syscall.SIGQUIT:
				fallthrough
			case syscall.SIGUSR2:
				log.Println("RELOAD")
				time.Sleep(1 * time.Second)

				conf, err := vc5.LoadConf(file)

				if err != nil {
					log.Println(err)
				} else {
					if h, err := hc.Reload(conf); err != nil {
						log.Println(err)
					} else {
						hc = h
						director.Update(hc)
						pool.Configure(conf.RHI)
					}
				}
			}
		}
	}()

	var stats *Stats
	start := time.Now()

	go func() {
		var t time.Time

		for {
			s := getStats(balancer)
			s.Sub(stats, time.Now().Sub(t))
			t = time.Now()
			stats = s
			if time.Now().Sub(start) > (time.Duration(conf.Learn) * time.Second) {
				var differ bool
				if rib, differ = s.RIBDiffer(rib); differ {
					pool.RIB(rib)
				}
			}
			time.Sleep(1 * time.Second)
		}
	}()

	if conf.Multicast != "" {
		go multicast_send(balancer, conf.Multicast)
		go multicast_recv(balancer, conf.Multicast)
	}

	var timestamp time.Time
	var mutex sync.Mutex
	prefixes := []byte("{}")

	static := http.FS(STATIC)
	var fs http.FileSystem

	if *root != "" {
		fs = http.FileSystem(http.Dir(*root))
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if fs != nil {
			file := r.URL.Path
			if file == "" || file == "/" {
				file = "/index.html"
			}

			if f, err := fs.Open("/" + file); err == nil {
				f.Close()
				http.FileServer(fs).ServeHTTP(w, r)
				return
			}
		}

		if defcon(w, r, balancer) {
			return
		}

		r.URL.Path = "static/" + r.URL.Path // there must be a way to avoid this, surely ...
		http.FileServer(static).ServeHTTP(w, r)
	})

	http.HandleFunc("/clear", func(w http.ResponseWriter, r *http.Request) {
		balancer.NoBlockList()
	})

	http.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		var list [PREFIXES]bool // contiguous list of /20s - "true" indicates block

		err = json.Unmarshal(b, &list)

		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		balancer.BlockList(list)
	})

	http.HandleFunc("/prefixes.json", func(w http.ResponseWriter, r *http.Request) {

		mutex.Lock()
		defer mutex.Unlock()
		now := time.Now()

		if now.Sub(timestamp) > (time.Second * 50) {
			p := balancer.Prefixes()
			j, err := json.Marshal(p)

			if err != nil {
				prefixes = []byte("{}")
			} else {
				prefixes = j
			}

			timestamp = now
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(prefixes)
	})

	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		for _, l := range logger.Dump() {
			w.Write([]byte(fmt.Sprintln(l)))
		}
	})

	http.HandleFunc("/conf.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, err := json.MarshalIndent(conf, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, err := json.MarshalIndent(hc, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cf := director.Status()
		j, err := json.MarshalIndent(cf, "", "  ")

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if j, _ := json.MarshalIndent(stats, "", "  "); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if stats == nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write(prometheus(stats, start))
		}
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		history := logger.Dump()

		re := regexp.MustCompile("^/log/([0-9]+)$")
		match := re.FindStringSubmatch(r.RequestURI)

		if match != nil && len(match) == 2 {
			n, _ := strconv.ParseInt(match[1], 10, 64)
			history = logger.Since(int64(n))
		}

		if j, err := json.MarshalIndent(history, "", "  "); err != nil {
			log.Println(err)
			w.Write([]byte(`[]`))
		} else {
			w.Write(j)
		}
		w.Write([]byte("\n"))
	})

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func defcon(w http.ResponseWriter, r *http.Request, lb *vc5.VC5) (ret bool) {

	var d uint8

	switch r.URL.Path {
	case "/defcon1":
		d = 1
	case "/defcon2":
		d = 2
	case "/defcon3":
		d = 3
	case "/defcon4":
		d = 4
	case "/defcon5":
		d = 5
	}

	if d == 0 {
		return
	}

	ret = true

	switch *auth {
	case "":
		w.WriteHeader(http.StatusNotFound)
		return
	case ":":
	default:
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(*auth))
		authorization, ok := r.Header["Authorization"]

		if !ok || len(authorization) < 1 || authorization[0] != basic {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	lb.DEFCON(d)
	w.WriteHeader(http.StatusOK)
	return
}

/**********************************************************************/

const maxDatagramSize = 1500

func multicast_send(lb *vc5.VC5, address string) {

	addr, err := net.ResolveUDPAddr("udp", address)

	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP("udp", nil, addr)

	if err != nil {
		log.Fatal(err)
	}

	conn.SetWriteBuffer(maxDatagramSize * 100)

	ticker := time.NewTicker(time.Millisecond * 10)

	var buff [maxDatagramSize]byte

	for {
		select {
		case <-ticker.C:
			n := 0

		read_queue:
			f := lb.FlowQueue()
			if len(f) > 0 {
				buff[n] = uint8(len(f))

				copy(buff[n+1:], f[:])
				n += 1 + len(f)
				if n < maxDatagramSize-100 {
					goto read_queue
				}
			}

			if n > 0 {
				conn.Write(buff[:n])
			}
		}
	}
}

func multicast_recv(lb *vc5.VC5, address string) {
	udp, err := net.ResolveUDPAddr("udp", address)

	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenMulticastUDP("udp", nil, udp)

	conn.SetReadBuffer(maxDatagramSize * 1000)

	buff := make([]byte, maxDatagramSize)

	for {
		nread, _, err := conn.ReadFromUDP(buff)
		if err == nil {
			for n := 0; n+1 < nread; {
				l := int(buff[n])
				o := n + 1
				n = o + l
				if l > 0 && n <= nread {
					lb.StoreFlow(buff[o:n])
				}
			}
		}
	}
}
