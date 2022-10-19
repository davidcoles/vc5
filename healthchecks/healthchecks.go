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
	"errors"
	"fmt"

	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/types"
)

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

type Service struct {
	Reals      map[uint16]Real
	Minimum    uint16
	Sticky     bool
	Leastconns bool
	Metadata   Metadata
	Local      Real
}

type Virtual struct {
	Metadata Metadata
	Services map[L4]Service
}

type Healthchecks struct {
	Virtual map[IP4]Virtual
	Backend map[uint16]IP4
	Mapping map[uint16][2]IP4
	xVLANs  map[uint16]uint16
	vlan    map[IP4]uint16
}

func (h *Healthchecks) VLAN(ip IP4) uint16 {
	return h.vlan[ip]
}

func (h *Healthchecks) NAT() map[uint16][2]IP4 {
	return h.Mapping
}

func nats(hc *Healthchecks, list [][2]IP4) (map[uint16][2]IP4, error) {
	old := map[uint16][2]IP4{}

	if hc != nil {
		old = hc.Mapping
	}

	new := map[[2]IP4]bool{}
	for _, v := range list {
		new[v] = true
	}

	o := map[[2]IP4]uint16{}
	r := map[uint16][2]IP4{}
	var n uint16
	for k, v := range old {
		o[v] = k
	}

	for k, _ := range new {
		if x, ok := o[k]; ok {
			r[x] = k
		} else {
		find:
			n++
			if n > 65000 {
				return nil, errors.New("NAT mapping limit exceeded")
			}

			if _, ok := old[n]; ok {
				goto find
			}

			r[n] = k
		}
	}

	return r, nil
}

func rips(hc *Healthchecks, new []IP4) (map[uint16]IP4, error) {

	old := map[uint16]IP4{}

	if hc != nil {
		old = hc.Backend
	}

	o := map[IP4]uint16{}
	r := map[uint16]IP4{}
	var n uint16

	for k, v := range old {
		o[v] = k
	}

	for _, k := range new {
		if x, ok := o[k]; ok {
			r[x] = k
		} else {
		find:
			n++
			if n > 255 {
				return nil, errors.New("Real server limit exceeded")
			}

			if _, ok := old[n]; ok {
				goto find
			}

			r[n] = k
		}
	}

	return r, nil
}

func (c *Healthchecks) _RIP(r IP4) uint16 {
	for k, v := range c.Backend {
		if v == r {
			return k
		}
	}

	return 0
}
func (c *Healthchecks) _NAT(vip, rip IP4) uint16 {
	for k, v := range c.Mapping {
		if v[0] == vip && v[1] == rip {
			return k
		}
	}

	return 0
}

func Load(c *config2.Conf) (*Healthchecks, error) {
	return _ConfHealthchecks(c, nil)
}

func (h *Healthchecks) Reload(c *config2.Conf) (*Healthchecks, error) {
	return _ConfHealthchecks(c, h)
}

func _ConfHealthchecks(c *config2.Conf, old *Healthchecks) (*Healthchecks, error) {
	var hc Healthchecks

	hc.Virtual = map[IP4]Virtual{}

	var err error = nil

	hc.Backend, err = rips(old, c.Reals())
	if err != nil {
		return nil, err
	}

	hc.vlan = c.Vlans()

	hc.Mapping, err = nats(old, c.Nats())
	if err != nil {
		return nil, err
	}

	ips := []IP4{}

	for vip, x := range c.VIPs {

		v := Virtual{Services: map[L4]Service{}}

		for l4, y := range x {
			reals := map[uint16]Real{}
			for rip, z := range y.RIPs {
				ips = append(ips, rip)
				r := hc._RIP(rip)
				n := hc._NAT(vip, rip)
				if r == 0 || n == 0 {
					msg := fmt.Sprintf("%s/%s: %d %d", vip.String(), rip.String(), r, n)
					return nil, errors.New(msg)
				}
				reals[r] = Real{RIP: rip, NAT: n, Checks: z.Checks()}
			}

			r := IP4{127, 0, 0, 1}
			n := hc._NAT(vip, r)
			local := Real{RIP: r, NAT: n, Checks: y.Local}

			m := Metadata{Name: y.Name, Description: y.Description}
			s := Service{Reals: reals, Metadata: m, Local: local, Minimum: y.Need}
			v.Services[l4] = s
		}

		hc.Virtual[vip] = v
	}

	return &hc, nil
}
