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

package healthchecks

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"unsafe"

	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/types"
)

type uP = unsafe.Pointer
type IP4 = types.IP4
type MAC = types.MAC
type L4 = types.L4
type Protocol = types.Protocol

type Checks = config2.Checks
type Check = config2.Check

type Metadata struct {
	Name        string
	Description string
}

type NAT struct {
	MAC MAC
	VIP IP4
	RIP IP4
	Loc bool
}

type Backend struct {
	MAC MAC
	IP  IP4
}
type Reals map[uint16]Real
type Real struct {
	NAT    uint16
	RIP    IP4
	Checks Checks
}

type Service_ struct {
	Reals      map[uint16]Real
	Minimum    uint16
	Sticky     bool
	Leastconns bool
	Metadata   Metadata
}

type Virtual_ struct {
	Metadata Metadata
	Services map[L4]Service_
}

type Healthchecks struct {
	Virtuals map[IP4]Virtual_
	Backends map[uint16]Backend
	Mapping  map[uint16][2]IP4
	Mappings map[uint16]NAT
}

//func (c *Conf) Healthchecks() (*Healthchecks, error) {
func ConfHealthchecks(c *config2.Conf) (*Healthchecks, error) {
	var hc Healthchecks

	hc.Virtuals = map[IP4]Virtual_{}

	ips := []IP4{}

	for vip, x := range c.VIPs {

		v := Virtual_{Services: map[L4]Service_{}}

		for l4, y := range x {
			reals := map[uint16]Real{}
			for rip, z := range y.RIPs {
				ips = append(ips, rip)
				r := c.RIP(rip)
				n := c.NAT(vip, rip)
				reals[r] = Real{RIP: rip, NAT: n, Checks: z.Checks()}

				if r == 0 || n == 0 {
					log.Fatal("real", vip, rip, r, n)
				}
			}

			m := Metadata{Name: y.Name, Description: y.Description}
			s := Service_{Reals: reals, Metadata: m}
			v.Services[l4] = s
		}

		hc.Virtuals[vip] = v
	}

	m := macs(ips)

	hc.Backends = map[uint16]Backend{}

	for k, v := range c.RIPs() {
		hc.Backends[k] = Backend{IP: v, MAC: m[v]}
	}

	hc.Mapping = map[uint16][2]IP4{}
	for k, v := range c.NATs() {
		hc.Mapping[k] = v
	}

	return &hc, nil
}

func read_macs(rip map[IP4]bool) (map[IP4]MAC, error) {

	ip2mac := make(map[IP4]MAC)
	ip2nic := make(map[IP4]*net.Interface)

	re := regexp.MustCompile(`^(\S+)\s+0x1\s+0x.\s+(\S+)\s+\S+\s+(\S+)$`)

	file, err := os.OpenFile("/proc/net/arp", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) > 3 {

			ip := net.ParseIP(m[1])

			if ip == nil {
				continue
			}

			ip = ip.To4()

			if ip == nil || len(ip) != 4 {
				continue
			}

			hw, err := net.ParseMAC(m[2])

			if err != nil || len(hw) != 6 {
				continue
			}

			iface, err := net.InterfaceByName(m[3])

			if err != nil {
				continue
			}

			var ip4 IP4
			var mac [6]byte

			copy(ip4[:], ip[:])
			copy(mac[:], hw[:])

			if ip4.String() == "0.0.0.0" {
				continue
			}

			if mac == [6]byte{0, 0, 0, 0, 0, 0} {
				continue
			}

			if _, ok := rip[ip4]; !ok {
				continue
			}

			ip2mac[ip4] = mac
			ip2nic[ip4] = iface
		}
	}

	return ip2mac, nil
}

func Macs(ips []IP4) map[IP4]MAC {
	return macs(ips)
}
func macs(ips []IP4) map[IP4]MAC {
	locals := map[IP4]bool{}
	hwaddr := map[IP4]MAC{}

	for _, v := range ips {
		locals[v] = false
	}

	for k, _ := range locals {
		hwaddr[k] = MAC{}
	}

	ifaces, err := net.Interfaces()

	if err == nil {

		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				log.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
				continue
			}
			for _, a := range addrs {

				ip, _, err := net.ParseCIDR(a.String())

				if err == nil {

					ip4 := ip.To4()

					if ip4 != nil {
						x := IP4{ip4[0], ip4[1], ip4[2], ip4[3]}

						if _, ok := locals[x]; ok {
							locals[x] = true
							var mac MAC
							copy(mac[:], i.HardwareAddr)
							hwaddr[x] = mac
						}
					}
				}
			}
		}
	}

	remote := map[IP4]bool{}

	for k, v := range locals {
		if !v {
			remote[k] = true
		}
	}

	r, err := read_macs(remote)

	if err == nil {
		for k, v := range r {
			hwaddr[k] = v
		}
	}

	return hwaddr
}
