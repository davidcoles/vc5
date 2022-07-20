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

package config2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type L4 = types.L4
type Check = types.Check
type Checks = types.Checks

type RIP struct {
	Http  []Check `json:"http,omitempty"`
	Https []Check `json:"https,omitempty"`
	Tcp   []Check `json:"tcp,omitempty"`
	Syn   []Check `json:"syn,omitempty"`
	Dns   []Check `json:"dns,omitempty"`
}

func (r *RIP) Checks() Checks {
	var c Checks
	c.Http = r.Http
	c.Https = r.Https
	c.Tcp = r.Tcp
	c.Syn = r.Syn
	c.Dns = r.Dns
	return c
}

type Serv struct {
	Name        string
	Description string
	Need        uint16
	Leastconns  bool
	Sticky      bool
	RIPs        map[IP4]RIP
}

type Conf struct {
	VIPs  map[IP4]map[L4]Serv
	VLANs map[uint16]string
	rip   map[uint16]IP4
	nat   map[uint16][2]IP4
	vid   map[uint16]uint16
	vlan  map[IP4]uint16
}

func load(file string) (*Conf, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var config Conf

	err = json.Unmarshal(b, &(config))
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func Load(file string, old *Conf) (*Conf, error) {

	if old == nil {
		old = &Conf{rip: map[uint16]IP4{}, nat: map[uint16][2]IP4{}}
	}

	c, err := load(file)

	c.vlan, err = c.vlans()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Conf) vlans() (map[IP4]uint16, error) {

	foo := map[IP4]uint16{}

	if len(c.VLANs) == 0 {
		return foo, nil
	}

	vlan := map[uint16]*net.IPNet{}

	for k, v := range c.VLANs {
		_, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}
		vlan[k] = ipnet
	}

	vid := map[uint16]uint16{}

rips:
	for n, i := range c.rip {
		for k, v := range vlan {
			if v.Contains(net.IPv4(i[0], i[1], i[2], i[3])) {
				vid[n] = k
				continue rips
			}
		}
		return foo, errors.New("No VLAN for " + i.String())
	}

rips2:
	for _, i := range c.Reals() {
		for k, v := range vlan {
			if v.Contains(net.IPv4(i[0], i[1], i[2], i[3])) {
				foo[i] = k
				continue rips2
			}
		}
		return foo, errors.New("No VLAN for " + i.String())
	}

	c.vid = vid

	fmt.Println(vid)

	return foo, nil
}

func (c *Conf) Vlans() map[IP4]uint16   { return c.vlan }
func (c *Conf) VIDs() map[uint16]uint16 { return c.vid }

/*
func (c *Conf) NATs() map[uint16][2]IP4 { return c.nat }
func (c *Conf) RIPs() map[uint16]IP4    { return c.rip }

func _nats(old map[uint16][2]IP4, new map[[2]IP4]bool) map[uint16][2]IP4 {
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
				panic("nats")
			}

			if _, ok := old[n]; ok {
				goto find
			}

			r[n] = k
		}
	}

	return r
}
*/
/*
func (c *Conf) _Reals() []IP4 {
	var l []IP4

	for _, ip := range c.RIPs() {
		l = append(l, ip)
	}

	return l
}
func (c *Conf) _Nats() [][2]IP4 {
	var l [][2]IP4

	for _, p := range c.NATs() {
		l = append(l, p)
	}

	return l
}
*/

func (c *Conf) Reals() []IP4 {

	real := map[IP4]bool{}

	for _, l := range c.VIPs {
		for _, s := range l {
			for r, _ := range s.RIPs {
				real[r] = false
			}
		}
	}

	var n []IP4
	for k, _ := range real {
		n = append(n, k)
	}

	return n
}

func (c *Conf) Nats() [][2]IP4 {

	nat := map[[2]IP4]bool{}

	for v, l := range c.VIPs {
		for _, s := range l {
			for r, _ := range s.RIPs {
				nat[[2]IP4{v, r}] = false
			}
		}
	}

	var n [][2]IP4
	for k, _ := range nat {
		n = append(n, k)
	}

	return n
}

/*
func _rips(old map[uint16]IP4, new map[IP4]bool) map[uint16]IP4 {
	o := map[IP4]uint16{}
	r := map[uint16]IP4{}
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
			if n > 255 {
				panic("rips")
			}

			if _, ok := old[n]; ok {
				goto find
			}

			r[n] = k
		}
	}

	return r
}

func (c *Conf) _RIP(r IP4) uint16 {
	for k, v := range c.rip {
		if v == r {
			return k
		}
	}

	return 0
}
func (c *Conf) _NAT(vip, rip IP4) uint16 {
	for k, v := range c.nat {
		if v[0] == vip && v[1] == rip {
			return k
		}
	}

	return 0
}
*/
