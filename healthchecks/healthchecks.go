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
	//"bufio"
	//"fmt"
	"log"
	//"net"
	//"os"
	//"regexp"
	//"unsafe"

	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/types"
)

//type uP = unsafe.Pointer
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
	VIP IP4
	RIP IP4
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
	Backends map[uint16]IP4
	Mapping  map[uint16][2]IP4
}

func (h *Healthchecks) NAT() map[uint16][2]IP4 {
	return h.Mapping
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

	hc.Backends = map[uint16]IP4{}

	for k, v := range c.RIPs() {
		hc.Backends[k] = v
	}

	hc.Mapping = map[uint16][2]IP4{}
	for k, v := range c.NATs() {
		hc.Mapping[k] = v
	}

	return &hc, nil
}
