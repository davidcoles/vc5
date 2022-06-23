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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type L4 = types.L4

type Checks struct {
	Http  []Check `json:"http,omitempty"`
	Https []Check `json:"https,omitempty"`
	Tcp   []Check `json:"tcp,omitempty"`
	Syn   []Check `json:"syn,omitempty"`
	Dns   []Check `json:"dns,omitempty"`
}

type Check struct {
	Path   string `json:"path"`
	Port   uint16 `json:"port"'`
	Expect uint32 `json:"expect"`
	Host   string `json:"host"`
}

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
	VIPs map[IP4]map[L4]Serv
	rip  map[uint16]IP4
	nat  map[uint16][2]IP4
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
	fmt.Println(c, err)

	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	fmt.Println(string(j), err)

	rip := map[IP4]bool{}
	nat := map[[2]IP4]bool{}

	for v, l := range c.VIPs {
		for l4, s := range l {
			for r, x := range s.RIPs {
				nat[[2]IP4{v, r}] = false
				rip[r] = false
				fmt.Println(v, l4, r, x)
			}
		}
	}

	c.rip = rips(old.rip, rip)
	c.nat = nats(old.nat, nat)

	return c, nil
}

func (c *Conf) NATs() map[uint16][2]IP4 { return c.nat }
func (c *Conf) RIPs() map[uint16]IP4    { return c.rip }

func nats(old map[uint16][2]IP4, new map[[2]IP4]bool) map[uint16][2]IP4 {
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

func rips(old map[uint16]IP4, new map[IP4]bool) map[uint16]IP4 {
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

func (c *Conf) RIP(r IP4) uint16 {
	for k, v := range c.rip {
		if v == r {
			return k
		}
	}

	return 0
}
func (c *Conf) NAT(vip, rip IP4) uint16 {
	for k, v := range c.nat {
		if v[0] == vip && v[1] == rip {
			return k
		}
	}

	return 0
}
