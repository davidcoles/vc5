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
	"encoding/json"
	//"errors"
	//"fmt"
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

type Backend struct {
	IP  IP4
	VID uint16
	Idx uint16
}

type Real struct {
	RIP    IP4 // get rid of this
	NAT    IP4
	MAC    MAC
	VID    uint16
	Checks Checks
	Probe  Probe
}

type Probe struct {
	Passed   bool
	Time     time.Time
	Duration time.Duration
	Message  string
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
	MAC   MAC
}

type vr [2]IP4

func (v vr) MarshalText() ([]byte, error) {
	return []byte(v[0].String() + "/" + v[1].String()), nil
}

type Healthchecks struct {
	Virtual map[IP4]Virtual `json:",omitempty"`
	_VID    map[IP4]uint16  `json:",omitempty"`
	VLAN    map[uint16]string
}

func Load(c *config2.Conf) (*Healthchecks, error) {
	return _ConfHealthchecks(c, nil)
}

func (h *Healthchecks) Reload(c *config2.Conf) (*Healthchecks, error) {
	return _ConfHealthchecks(c, h)
}

func (h *Healthchecks) VLANs() map[uint16]string { return h.VLAN }
func (h *Healthchecks) VID(r IP4) uint16         { return h._VID[r] }

func _ConfHealthchecks(c *config2.Conf, old *Healthchecks) (*Healthchecks, error) {

	var hc Healthchecks

	hc.Virtual = map[IP4]Virtual{}

	hc.VLAN = c.VLANs

	for vip, x := range c.VIPs {

		v := Virtual{Services: map[L4]Service{}}

		for l4, y := range x {

			reals := map[IP4]Real{}

			for rip, z := range y.RIPs {
				real := Real{RIP: rip, Checks: z.Checks()}
				reals[rip] = real
			}

			v.Services[l4] = Service{
				Metadata:       Metadata{Name: y.Name, Description: y.Description},
				FallbackChecks: y.Local,
				Fallback:       y.Fallback,
				Minimum:        y.Need,
				Sticky:         y.Sticky,
				Reals:          reals,
			}
		}

		hc.Virtual[vip] = v
	}

	hc.buildvid()

	return &hc, nil
}

func (h *Healthchecks) buildvid() {

	h._VID = map[IP4]uint16{}

	// determine which VLAN to use for each rip
	for be, _ := range h.RIPs() {
		if ok, vid := findvlan2(h.VLAN, be); ok {
			h._VID[be] = vid
		} else {
			h._VID[be] = 0
		}
	}

	// write vlan id to each rip entry in services
	for _, v := range h.Virtual {
		for _, s := range v.Services {
			for rip, real := range s.Reals {
				real.VID = h._VID[rip]
				s.Reals[rip] = real
			}
		}
	}
}

/**********************************************************************/

func ToNET(ipnet *net.IPNet) NET {
	n, _ := types.Net(ipnet.String())
	return n
}

func findvlan2(vlans map[uint16]string, ip IP4) (bool, uint16) {
	for vid, cidr := range vlans {

		_, ipnet, err := net.ParseCIDR(cidr)

		if err == nil {
			if ipnet.Contains(ip.IP()) {
				return true, vid
			}
		}
	}

	return false, 0
}

func (h *Healthchecks) DeepCopy() *Healthchecks {
	j, err := json.MarshalIndent(h, "", "  ")

	if err != nil {
		panic(err)
	}

	var n Healthchecks

	err = json.Unmarshal(j, &n)

	if err != nil {
		panic(err)
	}

	n.buildvid()

	return &n
}

func (h *Healthchecks) JSON() string {
	j, _ := json.MarshalIndent(h, "", "  ")
	return string(j)
}

func (h *Healthchecks) RIPs() map[IP4]IP4 {
	r := map[IP4]IP4{}
	for _, v := range h.Virtual {
		for _, s := range v.Services {
			for rip, _ := range s.Reals {
				r[rip] = rip
			}
		}
	}
	return r
}

func (h *Healthchecks) Tuples() map[[2]IP4]bool {
	n := map[[2]IP4]bool{}
	for vip, v := range h.Virtual {
		for _, s := range v.Services {
			for rip, _ := range s.Reals {
				n[[2]IP4{vip, rip}] = true
			}
		}
	}
	return n
}
