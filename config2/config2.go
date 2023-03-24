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
	//"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"

	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type NET = types.NET
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

type Serv struct {
	Name        string
	Description string
	Need        uint16
	Leastconns  bool
	Sticky      bool
	RIPs        map[IP4]RIP
	Local       Checks
	Fallback    bool
}

type RHI struct {
	AS_Number    uint16
	Hold_Time    uint16
	Peers        []string
	Communities_ []community `json:"communities,omitempty"`
}

type Conf struct {
	VIPs  map[IP4]map[L4]Serv
	VLANs map[uint16]NET
	RHI   RHI
	Learn uint16
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

type community uint32

func (c *community) UnmarshalJSON(data []byte) error {
	re := regexp.MustCompile(`^"(\d+):(\d+)"$`)

	m := re.FindStringSubmatch(string(data))

	if len(m) != 3 {
		return errors.New("Badly formed community")
	}

	asn, err := strconv.Atoi(m[1])
	if err != nil {
		return err
	}

	val, err := strconv.Atoi(m[2])
	if err != nil {
		return err
	}

	if asn < 0 || asn > 65535 || val < 0 || val > 65535 {
		return errors.New("Badly formed community")
	}

	*c = community(uint32(asn)<<16 | uint32(val))

	return nil
}

func (r *RHI) Communities() []uint32 {
	var c []uint32
	for _, v := range r.Communities_ {
		c = append(c, uint32(v))
	}
	return c
}

//type ipnet net.IPNet

type ipnet struct {
	IP   IP4
	Mask IP4
}

func (i *ipnet) mask() (ip IP4) {
	ip[0] = i.IP[0] & i.Mask[0]
	ip[1] = i.IP[1] & i.Mask[1]
	ip[2] = i.IP[2] & i.Mask[2]
	ip[3] = i.IP[3] & i.Mask[3]
	return
}

func (i *ipnet) IPNet() (ip net.IP, ipnet net.IPNet) {
	ip = net.IPv4(i.IP[0], i.IP[1], i.IP[2], i.IP[3])
	n := i.mask()
	ipnet.IP = net.IPv4(n[0], n[1], n[2], n[3])
	ipnet.Mask = net.IPv4Mask(i.Mask[0], i.Mask[1], i.Mask[2], i.Mask[3])
	return

}

func (c *ipnet) UnmarshalJSON(data []byte) error {

	re := regexp.MustCompile(`^"([^"]+)"$`)

	m := re.FindStringSubmatch(string(data))

	if len(m) != 2 {
		return errors.New("Badly formed CIDR")
	}

	ip, ipn, err := net.ParseCIDR(m[1])

	if err != nil {
		return err
	}

	ip4 := ip.To4()

	if len(ip4) != 4 || (ip4[0] == 0 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 0) {
		return errors.New("Invalid VLAN")
	}

	mask := ipn.Mask

	if len(mask) != 4 || (mask[0] == 0 && mask[1] == 0 && mask[2] == 0 && mask[3] == 0) {
		return errors.New("Invalid VLAN")
	}

	copy(c.IP[:], ip4[:])
	copy(c.Mask[:], mask[:])

	//x, y := c.IPNet()
	//fmt.Println("XXXX", ipn, ip, len(ip4), len(mask), *c, c.mask(), x, y)

	return nil
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

func Load(file string) (*Conf, error) {

	c, err := load(file)

	if err != nil {
		return nil, err
	}

	return c, nil
}

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
