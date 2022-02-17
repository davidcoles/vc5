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
	_ "embed"
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
	"unsafe"

	"encoding/json"

	//"vc5/bgp4"
	"vc5/config"
	"vc5/core"
	"vc5/logger"
	"vc5/manage"
	"vc5/probes"
	//"vc5/stats"
	"vc5/types"
	"vc5/xdp"
)

//go:embed bpf/simple.o
var SIMPLE_O []byte

//go:embed bpf/bpf.o
var BPF_O []byte

type IP4 = types.IP4

func main() {
	ulimit()

	//simple()
	//return

	logs := logger.NewLogger()

	isatty := flag.Bool("t", false, "isatty")
	native := flag.Bool("n", false, "native")
	bridge := flag.String("b", "", "bridge")
	flag.Parse()

	args := flag.Args()

	vip := IP4{10, 0, 0, 1}

	if len(args) == 1 {

		hup := make(chan os.Signal)
		signal.Notify(hup, os.Interrupt, syscall.SIGHUP)
		go func() {
			for _ = range hup {
			}
		}()
		probes.Daemon(args[0], vip.String())
	}

	fmt.Println(args)

	conffile := args[0]
	netns := args[1]
	veth := args[2]
	mac := args[3]
	ipv4 := args[4]
	peth := args[5:]

	if false {
		var nics []types.NIC

		re := regexp.MustCompile(`:`)

		for _, v := range peth {
			split := re.Split(v, 2)
			if len(split) != 2 {
				panic("nope")
			}

			ip, ipnet, err := net.ParseCIDR(split[1])
			if err != nil {
				panic("ParseCIDR " + split[1])
			}

			ifc, err := net.InterfaceByName(split[0])
			if err != nil {
				panic("net.InterfaceByName " + split[0])
			}

			nics = append(nics, types.NIC{Name: split[0], IP: ip, IPNet: *ipnet, Iface: *ifc})
		}

		fmt.Println(nics)
	}

	ipaddr, ok := parseIP(ipv4)
	if !ok {
		log.Fatal(ipv4)
	}

	var hwaddr [6]byte
	if hw, err := net.ParseMAC(mac); err != nil || len(hw) != 6 {
		panic(err)
	} else {
		copy(hwaddr[:], hw[:])
	}

	conf, err := config.LoadConfiguration(conffile, peth[0], ipaddr)

	if err != nil {
		panic(err)
	}

	if false {
		j, err := json.MarshalIndent(conf, "", "\t")
		if err != nil {
			panic(err)
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

	c := core.New(BPF_O, ipaddr, veth, vip, hwaddr, *native, *bridge != "", peth...)

	if conf.Multicast != "" {
		go multicast_recv(c, c.IPAddr()[3], conf.Multicast, *isatty)
	}

	// Set up probe server - runs in other network namespace
	go probes.Serve(netns)

	manager := manage.Bootstrap(conf, c, logs)
	var closed bool

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("Exiting ...")
		exec.Command("ip", "link", "delete", veth).Run()
		exec.Command("ip", "netns", "delete", netns).Run()
		closed = true
		close(manager)
		time.Sleep(10 * time.Second)
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

	if *bridge != "" {
		time.Sleep(3 * time.Second)
		exec.Command("ip", "link", "set", "dev", veth, "master", *bridge).Output()
	}

	multicast_send(c, c.IPAddr()[3], conf.Multicast)

	for {
		time.Sleep(1 * time.Second)
	}
}

func multicast_recv(control *core.Control, instance byte, srvAddr string, isatty bool) {
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

			for len(buff) >= core.FLOW_STATE {
				control.UpdateFlow(buff)
				buff = buff[core.FLOW_STATE:]
			}
		} else {
			if isatty {
				fmt.Print(pulse())
			}
		}

	}
}

func multicast_send(control *core.Control, instance byte, srvAddr string) {
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

func simple() {
	//x, e := xdp.Simple("enp130s0f1", bpf.BPF_simple, "xdp_main")
	x, e := xdp.Simple("enp130s0f1", SIMPLE_O, "xdp_main")

	type counter struct {
		count uint64
		time  uint64
	}

	m := x.FindMap("stats")

	if m == -1 {
		log.Fatal("not found")
	}

	if !x.CheckMap(m, 4, 16) {
		log.Fatal("incorrect size")
	}

	var zero uint32

	fmt.Println(x, e)

	for {
		var counters [16]counter

		xdp.BpfMapUpdateElem(m, unsafe.Pointer(&zero), unsafe.Pointer(&counters), xdp.BPF_ANY)

		time.Sleep(1 * time.Second)

		if xdp.BpfMapLookupElem(m, unsafe.Pointer(&zero), unsafe.Pointer(&counters)) != 0 {
			log.Fatal("oops")
		}

		var s uint64
		var t uint64

		for _, c := range counters {
			s += c.count
			t += c.time
		}

		if s > 0 {
			fmt.Println(t / s)
		} else {
			fmt.Println(0)
		}
	}
}

/*
func vip_status(c *Control, ip IP4, veth string, b *bgp4.Peers, rhi chan types.RHI, logs *logger.Logger) chan vipstatus {
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

			rhi <- types.RHI{Ip: ip, Up: up}

			if up != was {
				//fmt.Println("***** CHANGED", v, up)
				logs.NOTICE(fmt.Sprintf("VIP status change: %s -> %s", ip, ud(up)))

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

func ud(b bool) string {
	if b {
		return "up"
	}
	return "down"
}
*/
