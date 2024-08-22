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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/davidcoles/cue/mon"

	"vc5"
)

// XVS specific routines

type query struct {
	Address string    `json:"address"`
	Check   mon.Check `json:"check"`
}

type reply struct {
	OK         bool   `json:"ok"`
	Diagnostic string `json:"diagnostic"`
}

// spawn a server (specified by args) which runs in the network namespace - if it dies then restart it
//func spawn(logs *logger, netns string, args ...string) {
func spawn(logs vc5.Logger, netns string, args ...string) {
	F := "netns"
	for {
		logs.Event(vc5.INFO, F, "spawn", KV{"args": fmt.Sprint(args)})

		cmd := exec.Command("ip", append([]string{"netns", "exec", netns}, args...)...)
		_, _ = cmd.StdinPipe()
		stderr, _ := cmd.StderrPipe()
		stdout, _ := cmd.StdoutPipe()

		reader := func(s string, fh io.ReadCloser) {
			scanner := bufio.NewScanner(fh)
			for scanner.Scan() {
				logs.Event(vc5.WARNING, F, "child", KV{s: scanner.Text()})
			}
		}

		go reader("stderr", stderr)

		if err := cmd.Start(); err != nil {
			logs.Event(vc5.ERR, F, "daemon", KV{"error.message": err.Error()})
		} else {
			reader("stdout", stdout)

			if err := cmd.Wait(); err != nil {
				// logs.ERR(F, "Daemon", err)
				logs.Event(vc5.ERR, F, "daemon", KV{"error.message": err.Error()})
			}
		}

		logs.Event(vc5.ERR, F, "exit", KV{})

		time.Sleep(1 * time.Second)
	}
}

type nns struct {
	client *http.Client
}

func NetNS(socket string) *nns {
	return &nns{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socket)
				},
			},
		},
	}
}

func (n *nns) Probe(addr netip.Addr, check mon.Check) (bool, string) {

	buff := new(bytes.Buffer)
	err := json.NewEncoder(buff).Encode(&query{Address: addr.String(), Check: check})

	if err != nil {
		return false, "Internal error marshalling probe: " + err.Error()
	}

	resp, err := n.client.Post("http://unix/probe", "application/octet-stream", buff)

	if err != nil {
		return false, "Internal error contacting netns daemon: " + err.Error()
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var r reply

	err = json.Unmarshal(body, &r)

	if err != nil {
		r.Diagnostic = "unable to unmarshal reply: " + err.Error()
	}

	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("%d response: %s", resp.StatusCode, r.Diagnostic)
	}

	return r.OK, r.Diagnostic
}

// server to run in the network namespace - receive probes from unix socket, pass to the 'mon' object to execute
func netns(socket string, addr netip.Addr) {

	go func() {
		// if stdin is closed (parent dies) then exit
		reader := bufio.NewReader(os.Stdin)
		_, _, err := reader.ReadRune()

		if err != nil {
			os.Remove(socket)
			log.Fatal(err)
		}
	}()

	monitor, err := mon.New(addr, nil, nil, nil)

	if err != nil {
		log.Fatal(err)
	}

	os.Remove(socket)

	s, err := net.Listen("unix", socket)

	if err != nil {
		log.Fatal(err)
	}

	// temporary for testing purposes
	os.Remove("/tmp/vc5ns")
	os.Symlink(socket, "/tmp/vc5ns")

	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {

		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"ok":false,"diagnostic":"unable to read request body"}`))
			return
		}

		var q query
		var rep reply

		err = json.Unmarshal(body, &q)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"ok":false,"diagnostic":"unable to unmarshal probe"}`))
			return
		}

		addr, err := netip.ParseAddr(q.Address)

		if err == nil {
			rep.OK, rep.Diagnostic = monitor.Probe(addr, q.Check)
		} else {
			rep.Diagnostic = "probe request: " + err.Error()
		}

		js, err := json.Marshal(&rep)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"ok":false,"diagnostic":"unable to marshal response"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(js)
	})

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func ethtool(i string) {
	exec.Command("ethtool", "-K", i, "rx", "off").Output()
	exec.Command("ethtool", "-K", i, "tx", "off").Output()
	exec.Command("ethtool", "-K", i, "rxvlan", "off").Output()
	exec.Command("ethtool", "-K", i, "txvlan", "off").Output()
}

func mac(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

type KV = map[string]any
type Debug struct{ Log vc5.Logger }

var foo atomic.Uint64

func (d *Debug) NAT(tag map[netip.Addr]int16, arp map[netip.Addr][6]byte, vrn map[[2]netip.Addr]netip.Addr, nat map[netip.Addr]string, out []netip.Addr, in []string) {

	f := foo.Add(1)

	for k, v := range tag {
		d.Log.Event(vc5.DEBUG, "vlan", "update", KV{"run": f, "destintation.ip": k, "vlan.id": v})
	}

	for k, v := range arp {
		d.Log.Event(vc5.DEBUG, "arp", "update", KV{"run": f, "destintation.ip": k, "destintation.mac": mac(v)})
	}

	for k, v := range vrn {
		d.Log.Event(vc5.DEBUG, "map", "update", KV{"run": f, "service.ip": k[0], "destination.ip": k[1], "destination.nat.ip": v})
	}

	for k, v := range nat {
		d.Log.Event(vc5.DEBUG, "nat", "update", KV{"run": f, "nat": k, "info": v})
	}

	//for _, v := range out {
	//	d.Log.DEBUG("delete", KV{"run": f, "out": v})
	//}

	//for _, v := range in {
	//	d.Log.DEBUG("delete", KV{"run": f, "in": v})
	//}
}

func (d *Debug) Redirects(vlans map[uint16]string) {
	//f := foo.Add(1)
	//for k, v := range vlans {
	//	d.Log.DEBUG("nic", KV{"run": f, "vlan.id": k, "info": v})
	//}
}

func (d *Debug) Backend(vip netip.Addr, port uint16, protocol uint8, backends []byte, took time.Duration) {
	//if len(backends) > 32 {
	//	backends = backends[:32]
	//}
	//d.Log.DEBUG("backend", KV{"vip": vip, "port": port, "protocol": protocol, "backends": fmt.Sprint(backends), "took": took.String()})
}

const maxDatagramSize = 1500

func multicast(c Client, multicast string) {
	go multicast_send(c, multicast)
	go multicast_recv(c, multicast)
}

func multicast_send(c Client, address string) {

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

		read_flow:
			f := c.ReadFlow()
			if len(f) > 0 {
				buff[n] = uint8(len(f))

				copy(buff[n+1:], f[:])
				n += 1 + len(f)
				if n < maxDatagramSize-100 {
					goto read_flow
				}
			}

			if n > 0 {
				conn.Write(buff[:n])
			}
		}
	}
}

func multicast_recv(c Client, address string) {
	udp, err := net.ResolveUDPAddr("udp", address)

	if err != nil {
		log.Fatal(err)
	}

	s := []string{`|`, `/`, `-`, `\`}
	var x int

	conn, err := net.ListenMulticastUDP("udp", nil, udp)

	conn.SetReadBuffer(maxDatagramSize * 1000)

	buff := make([]byte, maxDatagramSize)

	for {
		nread, _, err := conn.ReadFromUDP(buff)
		fmt.Print(s[x%4] + "\b")
		x++
		if err == nil {
			for n := 0; n+1 < nread; {
				l := int(buff[n])
				o := n + 1
				n = o + l
				if l > 0 && n <= nread {
					c.WriteFlow(buff[o:n])
				}
			}
		}
	}
}

func readCommands(sock net.Listener, client Client, log vc5.Logger) {
	// eg.: echo reattach enp130s0f0 | socat - UNIX-CLIENT:/var/run/vc5
	F := "command"

	re := regexp.MustCompile(`\s+`)

	for {
		conn, err := sock.Accept()
		if err != nil {
			log.Event(vc5.ERR, F, "accept", KV{"error.message": err.Error()})
		} else {
			go func() {
				s := bufio.NewScanner(conn)

				for s.Scan() {

					line := s.Text()

					var cmd []string

					for _, s := range re.Split(line, -1) {
						if s != "" {
							cmd = append(cmd, s)
						}
					}

					l := len(cmd)

					if l < 1 {
						continue
					}

					switch cmd[0] {
					case "reattach":
						if l != 2 {
							fmt.Println("Usage: reattach <interface>")
							continue
						}

						nic := cmd[1]
						if err := client.ReattachBPF(nic); err != nil {
							log.Event(vc5.NOTICE, F, cmd[0], KV{"interface.name": nic, "error.message": err.Error()})
						} else {
							log.Event(vc5.NOTICE, F, cmd[0], KV{"interface.name": nic})
						}

					default:
						log.Event(vc5.NOTICE, F, cmd[0], KV{"error.message": "Unknown command"})
					}
				}
			}()
		}
	}
}
