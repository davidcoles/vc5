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
	"errors"
	"fmt"
	//"log"
	"net"
	"time"

	"github.com/davidcoles/vc5/types"
	"github.com/davidcoles/vc5/xdp"
)

type NAT struct {
	C      chan *Healthchecks
	Logger types.Logger
	Maps   *maps

	DefaultIP     IP4
	PhysicalMAC   MAC
	PhysicalIndex int

	VC5aIf int
	VC5aIP IP4
	VC5bIP IP4

	VC5aMAC MAC
	VC5bMAC MAC

	in    chan *Healthchecks
	pings map[IP4]chan bool
	maps  *maps
}

func (n *NAT) NAT(h *Healthchecks) (*Healthchecks, error) {
	n.C = make(chan *Healthchecks)
	n.in = make(chan *Healthchecks)

	n.pings = map[IP4]chan bool{}
	n.maps = n.Maps

	icmp := ICMP()

	if icmp == nil {
		return nil, errors.New("ICMP failed")
	}

	natMap := nats(nil, h.Tuples())

	go n.nat(h, natMap, icmp)

	return copyhc(n.VC5aIP, h, natMap, arp()), nil // fill in MACs + NAT addresses
}

func (n *NAT) Close() {
	close(n.in)
}

func invert(m map[[2]IP4]uint16) map[uint16][2]IP4 {
	n := map[uint16][2]IP4{}
	for k, v := range m {
		n[v] = k
	}
	return n
}

func (n *NAT) Configure(h *Healthchecks) {
	n.in <- h
}

type natkey struct {
	src_ip  IP4 //__be32 src_ip;
	dst_ip  IP4 //__be32 dst_ip;
	src_mac MAC //__u8 src_mac[6];
	dst_mac MAC //__u8 dst_mac[6];
}

type natval struct {
	ifindex uint32  //__u32 ifindex;
	src_ip  IP4     //__be32 src_ip;
	dst_ip  IP4     //__be32 dst_ip;
	vlan    uint16  //__u16 vlan;
	_pad    [2]byte //__u8 _pad[2];
	src_mac MAC     //__u8 src_mac[6];
	dst_mac MAC     //__u8 dst_mac[6];
}

func (n *natkey) String() string {
	return fmt.Sprintf("{%s %s %s %s}", n.src_ip, n.dst_ip, n.src_mac, n.dst_mac)
}

func (n *natval) String() string {
	return fmt.Sprintf("{%s %s %s %s %d %d}", n.src_ip, n.dst_ip, n.src_mac, n.dst_mac, n.vlan, n.ifindex)
}

func (n *NAT) nat(h *Healthchecks, natMap map[[2]IP4]uint16, icmp *ICMPs) {

	physip := n.DefaultIP

	vc5aip := n.VC5aIP
	vc5bip := n.VC5bIP

	vc5amac := n.VC5aMAC
	vc5bmac := n.VC5bMAC

	vethif := uint32(n.VC5aIf)

	ticker := time.NewTicker(5 * time.Second) // fire quickly first time
	defer ticker.Stop()
	defer close(n.C)
	defer icmp.Close()

	prev := map[natkey]bool{}
	redirect := map[uint16]int{}

	vlans, redirect, ifmacs := resolve_vlans(h.VLANs(), n.Logger)
	n.ping(h.RIPs(), icmp)  // start/stop pings
	time.Sleep(time.Second) // give ARP a second to resolve

	for {
		macs := arp() // update from ARP cache

		table := map[natkey]bool{}

		for vr, idx := range natMap {
			if idx == 0 {
				continue
			}

			vip := vr[0]
			rip := vr[1]
			nat := nat_addr(idx, vc5bip)

			physmac := n.PhysicalMAC
			physif := uint32(n.PhysicalIndex)

			realmac, _ := macs[rip]

			var vlanid uint16
			vlanip := physip

			if vlanid = h.VID(rip); vlanid != 0 {
				vlanip = IP4{}
				if ip, ok := vlans[vlanid]; ok {
					vlanip = ip
				}
			}

			n.Logger.DEBUG("nat", "vip/rip/vlanid/vlanip", vip, rip, vlanid, vlanip)

			if vlanid != 0 {
				physmac = ifmacs[vlanid]
				physif = uint32(redirect[vlanid])
			}

			// outgoing probes
			key := natkey{src_ip: vc5bip, src_mac: vc5bmac, dst_ip: nat, dst_mac: vc5amac}
			val := natval{src_ip: vlanip, src_mac: physmac, dst_ip: vip, dst_mac: realmac, ifindex: physif, vlan: vlanid}
			n.Logger.DEBUG("nat", "Outgoing map", key.String(), val.String())

			table[key] = true

			xdp.BpfMapUpdateElem(n.maps.nat(), uP(&key), uP(&val), xdp.BPF_ANY)

			if realmac.IsNil() {
				// write the out map for hosts with no arp to catch (and drop) on the way out, but don't put return map in
				n.Logger.DEBUG("nat", "VIP/RIP has no ARP entry", vip, rip, realmac)
				continue
			}

			// returning probes
			key = natkey{src_ip: vip, src_mac: realmac, dst_ip: vlanip, dst_mac: physmac}
			val = natval{src_ip: nat, src_mac: vc5amac, dst_ip: vc5bip, dst_mac: vc5bmac, ifindex: vethif}
			n.Logger.DEBUG("nat", "Returning map", key.String(), val.String())

			table[key] = true

			xdp.BpfMapUpdateElem(n.maps.nat(), uP(&key), uP(&val), xdp.BPF_ANY)
		}

		for k, _ := range prev {
			if _, ok := table[k]; !ok {
				xdp.BpfMapDeleteElem(n.maps.nat(), uP(&k))
			}
		}

		prev = table

		n.C <- copyhc(vc5aip, h, natMap, macs) // notify downstream of new config

		var ok bool
		select {
		case <-ticker.C:
			ticker.Reset(time.Minute)
		case h, ok = <-n.in:
			if !ok {
				return
			}

			n.ping(h.RIPs(), icmp) // start/stop pings

			vlans, redirect, ifmacs = resolve_vlans(h.VLANs(), n.Logger)

			natMap = nats(natMap, h.Tuples())

			time.Sleep(time.Second) // give ARP a second to resolve
		}
	}
}

func (n *NAT) ping(rips map[IP4]IP4, icmp *ICMPs) {

	for k, _ := range rips {
		if _, ok := n.pings[k]; !ok {
			n.Logger.NOTICE("icmp", "Starting ping for", k)
			//n.pings[k] = ping(icmp, k)
			n.pings[k] = make(chan bool)
			go func(done chan bool) {
				for {
					icmp.Ping(k.String())
					select {
					case <-time.After(10 * time.Second):
					case <-done:
						return
					}
				}
			}(n.pings[k])
		}
	}

	for k, v := range n.pings {
		if _, ok := rips[k]; !ok {
			n.Logger.NOTICE("icmp", "Stopping ping for", k)
			close(v)
			delete(n.pings, k)
		}
	}
}

func xping(icmp *ICMPs, ip IP4) chan bool {
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

func nats(old map[[2]IP4]uint16, new map[[2]IP4]bool) map[[2]IP4]uint16 {

	r := map[[2]IP4]uint16{}
	o := map[uint16][2]IP4{}

	for k, v := range old {
		if _, ok := new[k]; ok {
			if _, exists := o[v]; !exists {
				o[v] = k
				r[k] = v
			}
		}
	}

	var n uint16
	for k, _ := range new {
		if _, ok := r[k]; ok {
			continue
		}

	find:
		n++
		if n > 65000 {
			return r
		}

		if _, ok := o[n]; ok {
			goto find
		}

		r[k] = n
	}

	return r
}

func copyhc(ip IP4, h *Healthchecks, m map[[2]IP4]uint16, macs map[IP4]MAC) *Healthchecks {

	new := h.DeepCopy()

	for vip, v := range h.Virtual {
		for l4, s := range v.Services {
			for rip, r := range s.Reals {

				n, ok := m[[2]IP4{vip, rip}]

				if !ok || n == 0 {
					panic(fmt.Sprintf("NAT is 0: %s/%s", vip.String(), rip.String()))
				}

				r.NAT = nat_addr(n, ip)

				r.MAC = macs[rip]

				new.Virtual[vip].Services[l4].Reals[rip] = r
			}
		}
	}

	return new
}

func resolve_vlans(vlans map[uint16]string, logger types.Logger) (map[uint16]IP4, map[uint16]int, map[uint16]MAC) {
	ips := map[uint16]IP4{}
	ifaces := map[uint16]int{}
	macs := map[uint16]MAC{}

	for vid, prefix := range vlans {
		ip, iface, mac, ok := vlan_ip(prefix)
		if ok {
			ips[vid] = ip
			ifaces[vid] = iface
			macs[vid] = mac
		} else {
			logger.ERR("nat", "No IP for VLAN", vid)
		}
	}

	return ips, ifaces, macs
}

func vlan_ip(prefix string) (nul IP4, idx int, mac MAC, fail bool) {
	ifaces, err := net.Interfaces()

	if err != nil {
		return
	}

	for _, i := range ifaces {

		if i.Flags&net.FlagLoopback != 0 {
			continue
		}

		if i.Flags&net.FlagUp == 0 {
			continue
		}

		if i.Flags&net.FlagBroadcast == 0 {
			continue
		}

		if len(i.HardwareAddr) != 6 {
			continue
		}

		var mac MAC
		copy(mac[:], i.HardwareAddr[:])

		addr, err := i.Addrs()

		if err == nil {
			for _, a := range addr {
				cidr := a.String()
				ip, ipnet, err := net.ParseCIDR(cidr)
				if err == nil && ipnet.String() == prefix {

					ip4 := ip.To4()
					if len(ip4) == 4 && ip4 != nil {
						return IP4{ip4[0], ip4[1], ip4[2], ip4[3]}, i.Index, mac, true
					}
				}
			}
		}
	}

	return
}
