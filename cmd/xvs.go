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
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/davidcoles/cue/mon"
	"vc5"
)

// xvs specific routines

func mac(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

const maxDatagramSize = 1500

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
					c.WriteFlow(buff[o:n])
				}
			}
		}
	}
}

// return a function which will translate a vip/rip pair to a nat address - used by the manager to log destination.nat.ip
func nat(client Client) func(vip, rip netip.Addr) (netip.Addr, bool) {
	return func(vip, rip netip.Addr) (netip.Addr, bool) { return client.NAT(vip, rip), true }
}

// return a function which will relay probe requests to the network namespace healtchcheck proxy (which run against the nat address)
func prober(client Client, monitor *mon.Mon) func(netip.Addr, netip.Addr, vc5.Check) (ok bool, diagnostic string) {

	return func(vip, addr netip.Addr, check vc5.Check) (ok bool, diagnostic string) {
		if check.Host == "" {
			if vip.Is6() {
				check.Host = "[" + vip.String() + "]"
			} else {
				check.Host = vip.String()
			}

		}
		return monitor.Probe(addr, check)
	}
}
