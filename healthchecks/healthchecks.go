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

	"net"
)

type IP4 = types.IP4
type MAC = types.MAC
type NET = types.NET
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
	Index  uint16
}

type Service struct {
	Reals      map[IP4]Real
	Minimum    uint16
	Sticky     bool
	Leastconns bool
	Metadata   Metadata
	Local      Checks
	Fallback   bool
}

type Virtual struct {
	Metadata Metadata
	Services map[L4]Service
}

type Interface struct {
	Index int
	Name  string
	Addr  NET
}

type vr [2]IP4

func (v vr) MarshalText() ([]byte, error) {
	return []byte(v[0].String() + "/" + v[1].String()), nil
}

type Healthchecks struct {
	Virtual map[IP4]Virtual
	Backend map[IP4]uint16
	VID     map[IP4]uint16
	NATs    map[vr]uint16
	VLANs   map[uint16]Interface
	vlan    map[IP4]uint16
	Mode    bool
}

func (h *Healthchecks) VLAN(ip IP4) uint16 {
	return h.vlan[ip]
}

func (h *Healthchecks) NAT() map[uint16][2]IP4 {
	m := map[uint16][2]IP4{}
	for k, v := range h.NATs {
		m[v] = k
	}
	return m
}

func nats(hc *Healthchecks, list [][2]IP4) (map[uint16][2]IP4, error) {
	old := map[uint16][2]IP4{}

	if hc != nil {
		old = hc.NAT()
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

func (c *Healthchecks) Backends() map[uint16]IP4 {
	return c.backends()
}

func (c *Healthchecks) backends() map[uint16]IP4 {
	b := map[uint16]IP4{}
	for k, v := range c.Backend {
		b[v] = k
	}
	return b
}

func rips(c *Healthchecks, new []IP4) (map[uint16]IP4, error) {

	old := map[uint16]IP4{}

	if c != nil {
		old = c.backends()
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
	return c.Backend[r]
}

func (c *Healthchecks) _NAT(vip, rip IP4) uint16 {

	x, ok := c.NATs[[2]IP4{vip, rip}]

	if ok {
		return x
	}

	return 0

}

func Load(n NET, c *config2.Conf) (*Healthchecks, error) {
	return _ConfHealthchecks(n, c, nil)
}

func (h *Healthchecks) Reload(n NET, c *config2.Conf) (*Healthchecks, error) {
	return _ConfHealthchecks(n, c, h)
}

func _ConfHealthchecks(mynet NET, c *config2.Conf, old *Healthchecks) (*Healthchecks, error) {

	var hc Healthchecks

	hc.Virtual = map[IP4]Virtual{}

	//var err error = nil

	//hc.Backend, err = rips(old, c.Reals())
	_backend, err := rips(old, c.Reals())

	if err != nil {
		return nil, err
	}

	hc.Backend = map[IP4]uint16{}
	//for k, v := range hc.Backend {
	for k, v := range _backend {
		hc.Backend[v] = k
	}

	hc.vlan = c.Vlans()

	/**********************************************************************/

	fmt.Println(c.VLANs)

	hc.VLANs = map[uint16]Interface{}
	hc.VID = map[IP4]uint16{}

	if len(c.VLANs) == 0 {

		_, ipnet := mynet.IPNet()

		//for k, be := range hc.Backend {
		for k, be := range hc.backends() {
			fmt.Println(k, be)

			ip := net.IPv4(be[0], be[1], be[2], be[3])
			fmt.Println(ip, ipnet)

			if !ipnet.Contains(ip) {
				return nil, errors.New(fmt.Sprintln("No VLAN for", be))
			}

			hc.VID[be] = 0

		}

	} else {
		hc.Mode = true

		ifaces, _ := net.Interfaces()

		for _, i := range ifaces {
			fmt.Println(i)
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				n, err := types.Net(a.String())

				if err == nil {
					//fmt.Println("   ", n, err, n.Net())

					for k, v := range c.VLANs {

						if v.Net() == n.Net() {
							fmt.Println("iface", i.Name, "is a match for VLAN", k, a.String(), "is in ", v.Net())
							hc.VLANs[k] = Interface{Index: i.Index, Name: i.Name, Addr: n}
						}
					}
				}
			}
		}

		for k, _ := range c.VLANs {
			if _, ok := hc.VLANs[k]; !ok {
				return nil, errors.New(fmt.Sprint("No interface for VLAN", k))
			}
		}

	outer:
		//for k, be := range hc.Backend {
		for k, be := range hc.backends() {
			fmt.Println(k, be)
			for vid, iface := range hc.VLANs {
				ip := net.IPv4(be[0], be[1], be[2], be[3])
				_, ipnet := iface.Addr.IPNet()
				fmt.Println(ip, ipnet, vid)

				if ipnet.Contains(ip) {
					hc.VID[be] = vid
					fmt.Println(be, vid, iface)
					continue outer
				}
			}

			return nil, errors.New(fmt.Sprintln("No VLAN for", be))
		}
	}
	/**********************************************************************/

	mapping, err := nats(old, c.Nats())

	if err != nil {
		return nil, err
	}

	hc.NATs = map[vr]uint16{}
	for k, v := range mapping {
		hc.NATs[v] = k
	}

	ips := []IP4{}

	for vip, x := range c.VIPs {

		v := Virtual{Services: map[L4]Service{}}

		for l4, y := range x {
			reals := map[IP4]Real{}
			//xreals := map[uint16]Real{}
			for rip, z := range y.RIPs {
				ips = append(ips, rip)
				r := hc._RIP(rip)
				n := hc._NAT(vip, rip)
				if r == 0 || n == 0 {
					msg := fmt.Sprintf("%s/%s: %d %d", vip.String(), rip.String(), r, n)
					return nil, errors.New(msg)
				}

				real := Real{RIP: rip, NAT: n, Checks: z.Checks(), Index: r}
				//xreals[r] = real
				reals[rip] = real
			}

			m := Metadata{Name: y.Name, Description: y.Description}
			s := Service{Metadata: m, Local: y.Local, Fallback: y.Fallback, Minimum: y.Need, Sticky: y.Sticky, Reals: reals}
			v.Services[l4] = s
		}

		hc.Virtual[vip] = v
	}

	/**********************************************************************/
	return &hc, nil
}

func (c *Healthchecks) VlanID(r IP4, s IP4) (vid uint16, src IP4, ok bool) {
	src = s

	vid, ok = c.VID[r]

	if vid == 0 {
		return
	}

	i, o := c.VLANs[vid]

	if !o {
		return vid, src, false
	}

	src = i.Addr.IP

	return
}

func (c *Healthchecks) Iface(r IP4) (uint32, IP4, uint16) {
	var i IP4 = IP4{0, 0, 0, 0}

	vid, _ := c.VID[r]

	if vid == 0 {
		return 0, i, 0
	}

	vlan, ok := c.VLANs[vid]

	if !ok {
		return 0, i, 0
	}

	return uint32(vlan.Index), vlan.Addr.IP, vid
}
