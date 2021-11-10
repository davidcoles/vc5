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

	"bpf"

	"vc5/bgp4"
	"vc5/config"
	"vc5/core"
	"vc5/probes"
	"vc5/types"
	"vc5/xdp"
)

type IP4 = types.IP4
type Control = core.Control
type vipstatus = probes.Vipstatus

func simple() {
	x, e := xdp.Simple("enp130s0f1", bpf.BPF_simple, "xdp_main")
	fmt.Println(x, e)
	return

}

func main() {
	ulimit()

	//return simple()

	native := flag.Bool("n", false, "native")
	bridge := flag.String("b", "", "bridge")
	flag.Parse()

	args := flag.Args()

	if len(args) == 1 {
		probes.Daemon(args[0])
	}

	fmt.Println(args)

	conffile := args[0]
	netns := args[1]
	veth := args[2]
	mac := args[3]
	ipv4 := args[4]
	peth := args[5:]

	var hwaddr [6]byte

	ipaddr, ok := parseIP(ipv4)

	if !ok {
		log.Fatal(ipv4)
	}

	if hw, err := net.ParseMAC(mac); err != nil || len(hw) != 6 {
		panic(err)
	} else {
		copy(hwaddr[:], hw[:])
	}

	config, err := config.LoadConfigFile(conffile)
	//return

	if err != nil {
		panic(err)
	}

	c := core.New(ipaddr, veth, hwaddr, *native, *bridge != "", peth...)

	if config.Multicast != "" {
		go multicast_recv(c, c.IPAddr()[3], config.Multicast)
	}

	// Set up probe server - runs in other network namespace
	go probes.Serve(netns)

	// Set up BGP4 peer manager
	fmt.Println(config.Peers)
	b := bgp4.Manager(c.IPAddr(), config.RHI.RouterId, config.RHI.ASNumber, config.RHI.Peers)
	if len(config.RHI.Peers) == 0 {
		b = nil
	}

	ips := make(map[IP4]chan vipstatus)
	for _, s := range config.Services {
		fmt.Println("=========", s.Vip, s.Port)
		fmt.Println(s)

		ch, ok := ips[s.Vip]
		if !ok {
			ch = vip_status(c, s.Vip, veth, b)
			ips[s.Vip] = ch
		}

		go probes.MonitorVip(c, s, ch)
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("Exiting ...")
		exec.Command("ip", "link", "delete", veth).Run()
		exec.Command("ip", "netns", "delete", netns).Run()
		if b != nil {
			b.Close()
		}
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}()

	if *bridge != "" {
		time.Sleep(3 * time.Second)
		exec.Command("ip", "link", "set", "dev", veth, "master", *bridge).Output()
	}

	if config.Learn > 0 {
		time.Sleep(time.Duration(config.Learn) * time.Second)
	}

	if b != nil {
		b.Start()
	}

	multicast_send(c, c.IPAddr()[3], config.Multicast)

	for {
		time.Sleep(1 * time.Second)
	}
}

func vip_status(c *Control, ip IP4, veth string, b *bgp4.Peers) chan vipstatus {
	vs := make(chan vipstatus, 100)
	go func() {
		up := false
		m := make(map[uint16]bool)
		for v := range vs {
			m[v.Port] = v.Up
			was := up
			up = true

			for _, v := range m {
				if !v {
					up = false
				}
			}

			c.RHI() <- types.RHI{Ip: ip, Up: up}

			if up != was {
				fmt.Println("***** CHANGED", v, up)

				if b != nil {
					b.NLRI(ip, up)
				} else {
					if up {
						exec.Command("ip", "a", "add", ip.String()+"/32", "dev", veth).Output()
					} else {
						exec.Command("ip", "a", "del", ip.String()+"/32", "dev", veth).Output()
					}
				}

			}

		}
	}()
	return vs
}

func multicast_recv(control *Control, instance byte, srvAddr string) {
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
			fmt.Print(spin())

			for len(buff) >= core.FLOW_STATE {
				control.UpdateFlow(buff)
				buff = buff[core.FLOW_STATE:]
			}
		} else {
			fmt.Print(pulse())
		}

	}
}

func multicast_send(control *Control, instance byte, srvAddr string) {
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
