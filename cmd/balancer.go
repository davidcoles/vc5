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
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/mon"
	"github.com/davidcoles/xvs"
)

type Client = *xvs.Client
type Balancer struct {
	NetNS  *nns
	Logger *logger
	Client *xvs.Client
}

// interface method called by the director when the load balancer needs to be reconfigured
func (b *Balancer) Configure(services []cue.Service) error {

	target := map[tuple]cue.Service{}

	for _, s := range services {
		target[tuple{Address: s.Address, Port: s.Port, Protocol: s.Protocol}] = s

		for _, d := range s.Destinations {
			if s.Port != d.Port {
				return errors.New("Destination ports must match service ports for DSR")
			}
		}
	}

	svcs, _ := b.Client.Services()
	for _, s := range svcs {
		key := tuple{Address: s.Service.Address, Port: s.Service.Port, Protocol: s.Service.Protocol}
		if _, wanted := target[key]; !wanted {
			b.Client.RemoveService(s.Service)
		}
	}

	for _, s := range target {
		service := xvs.Service{Address: s.Address, Port: s.Port, Protocol: xvs.Protocol(s.Protocol), Sticky: s.Sticky}

		var dsts []xvs.Destination

		for _, d := range s.Destinations {
			if d.Port == s.Port {
				dsts = append(dsts, xvs.Destination{
					Address: d.Address,
					Weight:  d.HealthyWeight(),
				})
			}
		}

		b.Client.SetService(service, dsts)
	}

	return nil
}

// interface method alled by mon when a destination's heatlh status transistions up or down
func (b *Balancer) Notify(instance mon.Instance, state bool) {
	if logger := b.Logger; logger != nil {
		logger.NOTICE("notify", notifyLog(instance, state))
	}
}

// interface method called by mon when a destination needs to be probed - find the NAT address and probe that via the netns
func (b *Balancer) Probe(_ *mon.Mon, instance mon.Instance, check mon.Check) (ok bool, diagnostic string) {

	vip := instance.Service.Address
	rip := instance.Destination.Address
	nat, ok := b.Client.NATAddress(vip, rip)

	if !ok {
		diagnostic = "No NAT destination defined for " + vip.String() + "/" + rip.String()
	} else {
		ok, diagnostic = b.NetNS.Probe(nat, check)
	}

	if b.Logger != nil {
		b.Logger.DEBUG("probe", probeLog(instance, nat, check, ok, diagnostic))
	}

	return ok, diagnostic
}

func (b *Balancer) Multicast(multicast string) {
	go b.multicast_send(multicast)
	go b.multicast_recv(multicast)
}

const maxDatagramSize = 1500

func (b *Balancer) multicast_send(address string) {

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
			f := b.Client.ReadFlow()
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

func (b *Balancer) multicast_recv(address string) {
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
					b.Client.WriteFlow(buff[o:n])
				}
			}
		}
	}
}

func probeLog(instance mon.Instance, addr netip.Addr, check mon.Check, status bool, reason string) map[string]any {

	kv := map[string]any{
		"reason": reason,
		"status": updown(status),
		"proto":  proto(instance.Service.Protocol),
		"saddr":  instance.Service.Address.String(),
		"sport":  instance.Service.Port,
		"daddr":  instance.Destination.Address.String(),
		"dport":  instance.Destination.Port,
		"probe":  check.Type,
		"pport":  check.Port,
		"paddr":  addr,
	}

	switch check.Type {
	case "dns":
		if check.Method {
			kv["method"] = "tcp"
		} else {
			kv["method"] = "udp"
		}
	case "http":
		fallthrough
	case "https":
		if check.Method {
			kv["method"] = "HEAD"
		} else {
			kv["method"] = "GET"
		}

		if check.Host != "" {
			kv["host"] = check.Host
		}

		if check.Path != "" {
			kv["path"] = check.Path
		}

		if len(check.Expect) > 0 {
			kv["expect"] = fmt.Sprintf("%v", check.Expect)
		}
	}

	return kv
}

func notifyLog(instance mon.Instance, status bool) map[string]any {
	return map[string]any{
		"status": updown(status),
		"proto":  proto(instance.Service.Protocol),
		"saddr":  instance.Service.Address.String(),
		"sport":  instance.Service.Port,
		"daddr":  instance.Destination.Address.String(),
		"dport":  instance.Destination.Port,
	}
}

func proto(p uint8) string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return fmt.Sprintf("%d", p)
}
