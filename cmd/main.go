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
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/davidcoles/vc5"
)

func main() {
	ulimit()

	logs := vc5.NewLogger()

	isatty := flag.Bool("t", false, "isatty")
	native := flag.Bool("n", false, "native")
	bridge := flag.Bool("b", false, "bridge")
	ifname := flag.String("i", "", "ifname")
	passwd := flag.String("p", "", "passwd")

	lowwm := flag.Uint64("l", 0, "lowwm")
	highwm := flag.Uint64("h", 0, "highwm")
	defcon := flag.Uint("d", 5, "defcon")

	flag.Parse()

	args := flag.Args()

	vip1 := vc5.IP4{10, 255, 0, 1}
	vip2 := vc5.IP4{10, 255, 0, 2}

	if len(args) == 1 {

		hup := make(chan os.Signal)
		signal.Notify(hup, os.Interrupt, syscall.SIGHUP)
		go func() {
			for _ = range hup {
			}
		}()
		vc5.Daemon(args[0], vip1.String())
	}

	fmt.Println(args)

	conffile := args[0]
	ipv4 := args[1]
	peth := args[2:]

	netns := "vc5"
	veth := "vc5"

	ipaddr, ok := parseIP(ipv4)
	if !ok {
		log.Fatal(ipv4)
	}

	if *ifname == "" {
		*ifname = peth[0]
	}

	conf, err := vc5.LoadConfiguration(conffile, *ifname, ipaddr)

	if err != nil {
		log.Fatal(err)
	}

	if false {
		//if true {
		j, err := json.MarshalIndent(conf, "", "\t")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(j))

		return
	}

	fmt.Println("")
	for k, v := range conf.VIPs {
		for x, y := range v {
			fmt.Println(k, x, y)
		}
	}

	ws := ":80"
	if conf.Webserver != "" {
		ws = conf.Webserver
	}
	//webserver := stats.Server(ws, logs)
	webserver := vc5.Console(ws, logs, *passwd)

	time.Sleep(2 * time.Second) // will bomb if we can't bind to port

	mac, err := setup(netns, veth, vip1.String(), vip2.String(), peth...)
	defer cleanup(netns, veth, peth...)

	if err != nil {
		fmt.Println("Scripts failed:", err)
		return
	}

	c := vc5.New(veth, vip1, mac, *native, *bridge, peth...)
	c.Defcon(uint8(*defcon))

	go func() {
		for d := range webserver.DEFCON {
			c.Defcon(uint8(d))
		}
	}()

	//for some reason setting this before starting the program didn't work
	if *bridge {
		exec.Command("ip", "link", "set", "dev", veth, "master", *ifname).Output()
	}

	// weird behaviour ... maybe just bridge AND native mode???
	if *native {
		fmt.Println("Waiting for native mode to settle ...")
		time.Sleep(10 * time.Second)
	}

	if conf.Multicast != "" {
		go multicast_recv(c, ipaddr[3], conf.Multicast, *isatty)
	}

	// Set up probe server - runs in other network namespace
	go vc5.Serve(netns, logs)

	manager := vc5.Bootstrap(conf, c, logs, webserver)
	var closed bool

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("Exiting ...")
		//exec.Command("ip", "link", "delete", veth).Run()
		//exec.Command("ip", "netns", "delete", netns).Run()
		closed = true
		close(manager)
		time.Sleep(10 * time.Second)
		cleanup(netns, veth, peth...)
		os.Exit(1)
	}()

	hup := make(chan os.Signal)
	signal.Notify(hup, os.Interrupt, syscall.SIGHUP)
	go func() {
		for _ = range hup {
			fmt.Println("HUP")
			// reload config and apply
			new, err := conf.ReloadConfiguration(conffile)
			if err != nil {
				fmt.Println("Bad config", err)
			} else {
				conf = new
				time.Sleep(1 * time.Second)
				if !closed {
					manager <- conf
				}
			}
		}
	}()

	go multicast_send(c, ipaddr[3], conf.Multicast)

	prev := c.GlobalStats(false)

	for {
		time.Sleep(30 * time.Second)

		count := c.GlobalStats(false)
		defcon := c.Defcon(0)

		latency := count.Latency
		pps := (count.Rx_packets - prev.Rx_packets) / 30

		fmt.Printf("%d pps, %d ns avg. latency, DEFCON %d\n", pps, latency, defcon)

		// (12 core * 67ns) @ 75% = 603.00
		// (12 core * 67ns) @ 85% = 683.40

		if defcon > 1 && *highwm > 0 && latency > *highwm && pps > 100000 {
			defcon--
			c.Defcon(defcon)
			fmt.Println("DEFCON--", defcon)
		}

		if defcon < 5 && *lowwm > 0 && latency < *lowwm {
			defcon++
			c.Defcon(defcon)
			fmt.Println("DEFCON++", defcon)

		}

		prev = count
	}

}

func multicast_recv(control *vc5.Control, instance byte, srvAddr string, isatty bool) {
	maxDatagramSize := 1500

	addr, err := net.ResolveUDPAddr("udp", srvAddr)
	if err != nil {
		log.Fatal(err)
	}
	l, err := net.ListenMulticastUDP("udp", nil, addr)
	l.SetReadBuffer(maxDatagramSize)

	pulse := pulser()
	spin := spinner()

	for {
		buff := make([]byte, maxDatagramSize)
		n, src, err := l.ReadFromUDP(buff)
		if err != nil {
			log.Fatal("ReadFromUDP failed:", src, err)
		}
		buff = buff[0:n]

		inst := buff[0]
		buff = buff[1:]

		//fmt.Println("RECEIVED", instance, buff)
		if inst != instance {
			if isatty {
				fmt.Print(spin())
			}

			for len(buff) >= vc5.FLOW_STATE {
				control.UpdateFlow(buff)
				buff = buff[vc5.FLOW_STATE:]
			}
		} else {
			if isatty {
				fmt.Print(pulse())
			}
		}

	}
}

func multicast_send(control *vc5.Control, instance byte, srvAddr string) {
	if srvAddr == "" {
		for {
			if _, ok := control.FlowQueue(); ok {
				continue
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	var c *net.UDPConn

	addr, err := net.ResolveUDPAddr("udp", srvAddr)
	if err != nil {
		log.Fatal(err)
	}

	c, err = net.DialUDP("udp", nil, addr)
	if c == nil {
		log.Fatal(err)
	}

	for {

		var buff [1400]byte
		buff[0] = instance
		n := 1

	read_queue:
		if fq, ok := control.FlowQueue(); ok {
			copy(buff[n:], fq[:])
			//fmt.Println("***", fq)

			n += len(fq)

			if n < 1300 {
				goto read_queue
			}
		}

		if n > 1 {
			//fmt.Println("SENT", instance, n)
			c.Write(buff[:n])
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func spinner() func() string {
	var n int
	s := []string{" |\b\b", " /\b\b", " -\b\b", " \\\b\b"}
	return func() string {
		n++
		return s[n%len(s)]
	}
}

func pulser() func() string {
	var n int
	s := []string{" .\b\b", " o\b\b", " O\b\b", " o\b\b"}
	//s := []string{" O\b\b", " H\b\b", " Y\b\b", " E\b\b", " A\b\b", " H\b\b"}
	return func() string {
		n++
		return s[n%len(s)]
	}
}

func ulimit() {
	var rLimit syscall.Rlimit
	RLIMIT_MEMLOCK := 8
	if err := syscall.Getrlimit(RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatal("Error Getting Rlimit ", err)
	}
	rLimit.Max = 0xffffffffffffffff
	rLimit.Cur = 0xffffffffffffffff
	if err := syscall.Setrlimit(RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatal("Error Setting Rlimit ", err)
	}
}

func parseIP(ip string) ([4]byte, bool) {
	var addr [4]byte
	re := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)\.(\d+)$`)
	m := re.FindStringSubmatch(ip)
	if len(m) != 5 {
		return addr, false
	}
	for n, _ := range addr {
		a, err := strconv.ParseInt(m[n+1], 10, 9)
		if err != nil || a < 0 || a > 255 {
			return addr, false
		}
		addr[n] = byte(a)
	}
	return addr, true
}

func setup(netns, veth, vip1, vip2 string, nics ...string) ([6]byte, error) {
	var mac [6]byte
	var be string = veth + "b"

	script1 := `
ip link del ` + veth + ` || true
ip netns del ` + netns + ` || true
ip link add ` + veth + ` type veth peer name ` + be + `
ip l set ` + veth + ` up
ip a add ` + vip2 + `/30 dev ` + veth + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		return mac, err
	}

	iface, err := net.InterfaceByName(be)
	if err != nil {
		return mac, err
	}

	copy(mac[:], iface.HardwareAddr[:])

	script2 := `
ip netns add ` + netns + `
ip link set ` + be + ` netns ` + netns + `
`
	_, err = exec.Command("/bin/sh", "-e", "-c", script2).Output()
	if err != nil {
		return mac, err
	}

	script3 := `
ip netns exec ` + netns + ` /bin/bash <<EOF
ip l set ` + be + ` up
ip a add ` + vip1 + `/30 dev ` + be + `
ip r replace default via ` + vip2 + ` dev ` + be + `
ethtool -K ` + be + ` tx off >/dev/null
`
	// ip r replace 10.1.0.0/16 via ` + vip2 + ` dev vc5_2

	_, err = exec.Command("ip", "netns", "exec", netns, "/bin/sh", "-e", "-c", script3).Output()
	if err != nil {
		return mac, err
	}

	for _, nic := range nics {
		script4 := `
ip link set dev ` + nic + ` xdpgeneric off >/dev/null 2>&1 || true
ip link set dev ` + nic + ` xdpdrv     off >/dev/null 2>&1 || true
ethtool -K ` + nic + ` rxvlan off >/dev/null 2>&1 || true
`

		_, err = exec.Command("/bin/sh", "-e", "-c", script4).Output()
		if err != nil {
			return mac, err
		}
	}

	return mac, nil
}

func cleanup(netns, veth string, nics ...string) {
	script1 := `
ip link del ` + veth + ` || true
ip netns del ` + netns + ` || true
`

	exec.Command("/bin/sh", "-e", "-c", script1).Output()

	for _, nic := range nics {
		script2 := `
ip link set dev ` + nic + ` xdpgeneric off >/dev/null 2>&1 || true
ip link set dev ` + nic + ` xdpdrv     off >/dev/null 2>&1 || true
`
		exec.Command("/bin/sh", "-e", "-c", script2).Output()
	}

}
