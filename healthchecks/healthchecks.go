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
	"net"
	"time"

	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type MAC = types.MAC
type NET = types.NET
type L4 = types.L4
type Protocol = types.Protocol
type Checks = config2.Checks
type Check = config2.Check

type Metadata struct {
	Name        string `json:",omitempty"`
	Description string `json:",omitempty"`
}

type NAT struct {
	VIP IP4
	RIP IP4
}

type Backend struct {
	IP  IP4
	MAC MAC
	VID uint16
	Idx uint16
}

type Real struct {
	NAT    uint16
	RIP    IP4 // get rid of this
	Checks Checks
	Index  uint16
	Probe  Probe
}

type Probe struct {
	Passed   bool
	Time     time.Time
	Duration time.Duration
}

type Service struct {
	Metadata         Metadata
	Minimum          uint16
	Healthy          bool
	Sticky           bool
	Fallback         bool
	FallbackOn       bool
	FallbackProbe    Probe
	FallbackChecks   Checks
	Leastconns       bool
	LeastconnsIP     IP4
	LeastconnsWeight uint8
	Reals            map[IP4]Real `json:",omitempty"`
}

type Virtual struct {
	Metadata Metadata
	Healthy  bool
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
	Virtual    map[IP4]Virtual      `json:",omitempty"`
	Backend    map[IP4]uint16       `json:",omitempty"`
	Backends   map[IP4]Backend      `json:",omitempty"`
	VID        map[IP4]uint16       `json:",omitempty"`
	NATs       map[vr]uint16        `json:",omitempty"`
	VLANs      map[uint16]Interface `json:",omitempty"`
	Interfaces map[int]Interface    `json:",omitempty"`
	Egress     map[IP4]int          `json:",omitempty"`
	VLANMode   bool
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

func (c *Healthchecks) BackendIdx() map[uint16]IP4 {
	return c.backends()
}

func (c *Healthchecks) backends() map[uint16]IP4 {
	b := map[uint16]IP4{}
	for k, v := range c.Backend {
		b[v] = k
	}
	return b
}

func rips(c *Healthchecks, new_ []IP4) (map[uint16]IP4, error) {

	new := map[IP4]bool{}

	for _, ip := range new_ {
		new[ip] = true
	}

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

	for k, _ := range new {
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

	_backend, err := rips(old, c.Reals())

	if err != nil {
		return nil, err
	}

	hc.Backend = map[IP4]uint16{}
	for k, v := range _backend {
		hc.Backend[v] = k
	}

	//hc.vlan = c.Vlans()

	/**********************************************************************/

	hc.VLANs = map[uint16]Interface{}
	hc.VID = map[IP4]uint16{}
	//hc.Interfaces = map[int]Interface{}
	//hc.Egress = map[IP4]int{}

	_, ipnet := mynet.IPNet()
	hw := HWInventory()

	hc.VLANMode = len(c.VLANs) > 0

	if !hc.VLANMode {

		// In simple mode - ensure that every backend is in our subnet
		for be, _ := range hc.Backend {
			if ip := net.IPv4(be[0], be[1], be[2], be[3]); ipnet.Contains(ip) {
				hc.VID[be] = 0
			} else {
				return nil, errors.New(fmt.Sprint("No VLAN for", be))
			}
		}

	} else {

		// In VLAN mode - find IP address, MAC and interface to send probes from
		for vlanid, subnet := range c.VLANs {
			if ok, name, index, addr, _ := hw.MatchSubnet(subnet); ok {
				hc.VLANs[vlanid] = Interface{Index: index, Name: name, Addr: addr}
			} else {
				return nil, errors.New(fmt.Sprint("No interface for VLAN", vlanid))
			}
		}

		// Determine which VLAN ID to use for each backend
		for be, _ := range hc.Backend {
			if ok, vid := findvlan(hc.VLANs, be); ok {
				hc.VID[be] = vid
			} else {
				return nil, errors.New(fmt.Sprint("No VLAN for", be))
			}
		}
	}

	/**********************************************************************

	// In multi-NIC mode, determine which ifindex to bpf_redirect traffic to, and IP address, MAC to send probes from
	for be, _ := range hc.Backend {
		if ok, name, index, addr, _ := hw.MatchIP4(be); ok {
			hc.Interfaces[index] = Interface{Index: index, Name: name, Addr: addr}
			hc.Egress[be] = index
		} else {
			return nil, errors.New(fmt.Sprint("No interface for backend", be))
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
			for rip, z := range y.RIPs {
				ips = append(ips, rip)
				r := hc._RIP(rip)
				n := hc._NAT(vip, rip)
				if r == 0 || n == 0 {
					msg := fmt.Sprintf("%s/%s: %d %d", vip.String(), rip.String(), r, n)
					return nil, errors.New(msg)
				}

				real := Real{RIP: rip, NAT: n, Checks: z.Checks(), Index: r}
				reals[rip] = real
			}

			m := Metadata{Name: y.Name, Description: y.Description}
			s := Service{Metadata: m, FallbackChecks: y.Local, Fallback: y.Fallback, Minimum: y.Need, Sticky: y.Sticky, Reals: reals}
			v.Services[l4] = s
		}

		hc.Virtual[vip] = v
	}

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

/**********************************************************************/

type HW []IF

type IF struct {
	Index int
	Name  string
	MAC   [6]byte
	Addrs []AD
}

type AD struct {
	CIDR  string
	NET   NET
	IP    net.IP
	IPNet *net.IPNet
}

func (ifs HW) MatchIP(ip net.IP) (bool, string, int, NET, [6]byte) {
	for _, i := range ifs {
		for _, a := range i.Addrs {
			if a.IPNet.Contains(ip) {
				return true, i.Name, i.Index, a.NET, i.MAC
			}
		}
	}

	return false, "", 0, NET{}, [6]byte{}
}

func (ifs HW) MatchIP4(i IP4) (bool, string, int, NET, [6]byte) {
	ip := net.IPv4(i[0], i[1], i[2], i[3])
	for _, i := range ifs {
		for _, a := range i.Addrs {
			if a.IPNet.Contains(ip) {
				return true, i.Name, i.Index, a.NET, i.MAC
			}
		}
	}

	return false, "", 0, NET{}, [6]byte{}
}

func (ifs HW) MatchIPNet(ipn *net.IPNet) (bool, string, int, NET, [6]byte) {
	for _, i := range ifs {
		for _, a := range i.Addrs {
			if a.IPNet.String() == ipn.String() {
				return true, i.Name, i.Index, a.NET, i.MAC
			}
		}
	}

	return false, "", 0, NET{}, [6]byte{}
}

func (ifs HW) MatchSubnet(n NET) (bool, string, int, NET, [6]byte) {
	_, ipnet := n.IPNet()
	for _, i := range ifs {
		for _, a := range i.Addrs {
			if a.IPNet.String() == ipnet.String() {
				return true, i.Name, i.Index, a.NET, i.MAC
			}
		}
	}

	return false, "", 0, NET{}, [6]byte{}
}

func HWInventory() HW {
	ifaces, err := net.Interfaces()

	if err != nil {
		return nil
	}

	var hw []IF

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

		addr, err := i.Addrs()

		var ad []AD

		if err == nil {
			for _, a := range addr {
				cidr := a.String()
				ip, ipnet, err := net.ParseCIDR(cidr)
				if err == nil {

					n, err := types.Net(cidr)

					if err == nil && ip.To4() != nil {

						ad = append(ad, AD{CIDR: cidr, NET: n, IP: ip.To4(), IPNet: ipnet})
					}
				}
			}
		}

		var mac [6]byte

		copy(mac[:], i.HardwareAddr)

		hw = append(hw, IF{Index: i.Index, Name: i.Name, MAC: mac, Addrs: ad})
	}

	return hw
}

func ToNET(ipnet *net.IPNet) NET {
	n, _ := types.Net(ipnet.String())
	return n
}

func findvlan(vlans map[uint16]Interface, be IP4) (bool, uint16) {
	for vid, iface := range vlans {
		ip := net.IPv4(be[0], be[1], be[2], be[3])
		_, ipnet := iface.Addr.IPNet()

		if ipnet.Contains(ip) {
			return true, vid
		}
	}

	return false, 0
}
