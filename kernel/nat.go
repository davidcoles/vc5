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

package kernel

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/davidcoles/vc5/types"
	"github.com/davidcoles/vc5/xdp"
)

func (m *maps) NAT(l types.Logger, myip IP4, h *Healthchecks, egress, veth int, vc5aip, vc5bip IP4, vc5amac, vc5bmac MAC) (chan *Healthchecks, func(ip IP4) (MAC, bool)) {
	F := "nat"

	var mu sync.Mutex

	macs := map[IP4]MAC{}
	local := map[IP4]MAC{}

	ch := make(chan *Healthchecks)

	get_mac_for_ip := func(ip IP4) (MAC, bool) {
		mu.Lock()
		m, ok := macs[ip]
		mu.Unlock()
		return m, ok
	}

	macs = arp_macs()
	local = local_macs()

	go func() {
		time.Sleep(2 * time.Second)
		for {
			m := arp_macs()
			mu.Lock()
			macs = m
			mu.Unlock()

			select {
			case <-time.After(10 * time.Second):
			}
		}
	}()

	go func() {

		type record struct {
			vm  bpf_vipmac
			in  bpf_nat
			out bpf_nat
		}

		pings := map[IP4]chan bool{}
		recs := map[uint16]record{}

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		icmp := ICMP()

		for {

			select {
			case <-ticker.C:
			case x, ok := <-ch:
				ticker.Reset(20 * time.Second)
				if !ok {
					return
				}
				h = x
			}

			mapping := h.NAT()

			{
				rips := map[IP4]bool{}
				for _, be := range mapping {
					rips[be[1]] = true
				}

				for k, _ := range rips {
					if _, ok := pings[k]; !ok {
						//pings[k] = ping(k)
						l.NOTICE(F, "Starting ping for", k)
						pings[k] = ping(icmp, k)
					}
				}

				for k, v := range pings {
					if _, ok := rips[k]; !ok {
						close(v)
						delete(pings, k)
					}
				}
			}

			for n, be := range mapping {
				localhost := IP4{127, 0, 0, 1}

				vip := be[0]
				rip := be[1]
				nat := Nat(n, vc5bip)

				if rip == localhost {
					fmt.Println("******************** OBSOLETE")
					continue
				}

				mac, _ := get_mac_for_ip(rip)
				vm := bpf_vipmac{vip: vip, mac: mac}

				mymac, ok := local[myip]

				if !ok {
					log.Fatal(myip, mymac, ok)
				}

				vid, srcip, ok := h.VlanID(rip, myip)

				if !ok {
					fmt.Println("******************** VLAN ID not found", vip, rip, vid, srcip)
					continue
				}

				//fmt.Println("INDEX", rip, nat, egress, mac, vid)
				l.INFO("nat", rip, nat, egress, mac, vid)

				out := bpf_nat{vip: vip, mac: mac, srcmac: mymac, srcip: srcip, ifindex: uint32(egress), vid: vid}
				in := bpf_nat{vip: vc5bip, mac: vc5bmac, srcip: nat, ifindex: uint32(veth)}

				//fmt.Println("OUT", nat, out)
				//fmt.Println("IN", vm, in)

				var update bool = true
				rec := record{vm: vm, in: in, out: out}

				if v, ok := recs[n]; ok {
					if v == rec {
						update = false
					} else {
						if v.vm != rec.vm {
							//fmt.Println("UPDATING", v.vm)
							l.NOTICE("nat", "updating", v.vm, "to", rec.vm)
							xdp.BpfMapDeleteElem(m.vip_mac_to_nat(), uP(&(v.vm)))
						}
					}
				}

				recs[n] = rec

				if update {
					//fmt.Println("WRITING", nat, rip, vm)
					l.NOTICE("nat", "writing", nat, rip, vm)
					xdp.BpfMapUpdateElem(m.nat_to_vip_mac(), uP(&nat), uP(&out), xdp.BPF_ANY)
					xdp.BpfMapUpdateElem(m.vip_mac_to_nat(), uP(&vm), uP(&in), xdp.BPF_ANY)
				}
			}

			for n, v := range recs {
				if _, ok := mapping[n]; !ok {
					delete(recs, n)
					nat := Nat(n, vc5bip)
					//fmt.Println("REMOVING", nat, v.vm)
					l.NOTICE("nat", "writing", nat, v.vm)
					xdp.BpfMapDeleteElem(m.nat_to_vip_mac(), uP(&nat))
					xdp.BpfMapDeleteElem(m.vip_mac_to_nat(), uP(&(v.vm)))
				}
			}
		}
	}()

	ch <- h
	return ch, get_mac_for_ip
}

func ping(icmp *ICMPs, ip IP4) chan bool {
	// no need to receive a reply - this is only to populate the ARP cache
	done := make(chan bool)
	go func() {
		for {
			icmp.Ping(ip.String())
			select {
			case <-time.After(10 * time.Second):
			case <-done:
				return
			}
		}
	}()
	return done
}

/**********************************************************************/

func EchoRequest() []byte {

	var csum uint32
	wb := make([]byte, 8)

	wb[0] = 8
	wb[1] = 0

	for n := 0; n < 8; n += 2 {
		csum += uint32(uint16(wb[n])<<8 | uint16(wb[n+1]))
	}

	var cs uint16

	cs = uint16(csum>>16) + uint16(csum&0xffff)
	cs = ^cs

	wb[2] = byte(cs >> 8)
	wb[3] = byte(cs & 0xff)

	return wb
}

type ICMPs struct {
	submit chan string
}

//func ICMP(source string) *ICMPs {
func ICMP() *ICMPs {

	var icmp ICMPs

	c, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		log.Fatalf("listen err, %s", err)
	}

	icmp.submit = make(chan string, 1000)
	go icmp.probe(c)

	return &icmp
}

func (s *ICMPs) probe(socket net.PacketConn) {

	defer socket.Close()

	for target := range s.submit {

		socket.SetWriteDeadline(time.Now().Add(1 * time.Second))

		if _, err := socket.WriteTo(EchoRequest(), &net.IPAddr{IP: net.ParseIP(target)}); err != nil {
			log.Fatalf("WriteTo err, %s", err)
		}
	}
}

func (s *ICMPs) Ping(target string) {
	select {
	case s.submit <- target:
	default:
	}
}
