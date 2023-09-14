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
	//"fmt"
	"net"
	"time"

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type MAC = types.MAC
type NET = types.NET
type L4 = types.L4
type Protocol = types.Protocol
type IPPort = types.IPPort

type Checks = config.Checks
type Check = config.Check

type Metadata struct {
	Name        string `json:",omitempty"`
	Description string `json:",omitempty"`
}

type Backend struct {
	IP   IP4
	Port uint16
}

type Real struct {
	RIP  IP4
	Port uint16

	NAT      IP4
	MAC      MAC
	VID      uint16
	Checks   Checks
	XProbe   Probe
	Disabled bool
}

func (r *Real) IPPort() IPPort {
	return IPPort{IP: r.RIP, Port: r.Port}
}

func (r *Real) Probe() Probe {
	return r.XProbe
}

func (r *Real) SetProbe(p Probe) {
	r.XProbe = p
}

type Probe struct {
	Passed   bool
	Time     time.Time
	Duration time.Duration
	Message  string
}

type Service struct {
	VIP  IP4
	Port uint16
	UDP  bool

	Metadata         Metadata
	Minimum          uint16
	Healthy          bool
	Change           time.Time
	Scheduler        types.Scheduler
	Sticky           bool
	Fallback         bool
	FallbackOn       bool
	FallbackProbe    Probe
	FallbackChecks   Checks
	Leastconns       bool
	LeastconnsIP     IP4
	LeastconnsWeight uint8
	Backend          map[IPPort]Real `json:",omitempty"`
}

type Destination struct {
	Address IP4
	Port    uint16
	Up      bool
}

func (s *Service) Destinations() []Destination {
	var ret []Destination
	for _, r := range s.reals() {
		d := Destination{
			Address: r.RIP,
			Port:    r.Port,
			Up:      r.Probe().Passed && !r.Disabled,
		}
		ret = append(ret, d)
	}
	return ret
}

type SVC struct {
	VIP      IP4
	Port     uint16
	Protocol Protocol
}

func (s *SVC) L4() L4 {
	return L4{Port: s.Port, Protocol: s.Protocol}
}

type Up struct {
	Up   bool
	Time time.Time
}

func (h *Healthchecks) Health() map[IP4]Up {
	ret := map[IP4]Up{}

	for vip, v := range h.Virtual {
		ret[vip] = Up{Up: v.Healthy, Time: v.Change}
	}

	return ret
}

func (h *Healthchecks) Services() map[SVC]Service {
	ret := map[SVC]Service{}

	for vip, v := range h.Virtual {
		for l4, s := range v.Services {
			f := SVC{VIP: vip, Port: l4.Port, Protocol: l4.Protocol}

			s.VIP = vip
			s.Port = l4.Port
			s.UDP = false

			if l4.Protocol == types.UDP {
				s.UDP = true
			}

			ret[f] = s
		}
	}

	return ret
}

func (h *Healthchecks) Services_() []SVC {
	var ret []SVC

	for vip, v := range h.Virtual {
		for l4, _ := range v.Services {
			ret = append(ret, SVC{VIP: vip, Port: l4.Port, Protocol: l4.Protocol})
		}
	}

	return ret
}

func (s *Service) xReals___() map[IPPort]Real {
	return s.reals()
}

func (s *Service) Reals() []Real {
	var ret []Real
	for _, r := range s.reals() {
		ret = append(ret, r)
	}
	return ret
}

func (h *Healthchecks) Reals(svc SVC) []Real {

	var ret []Real

	v, ok := h.Virtual[svc.VIP]

	if !ok {
		return ret
	}

	l4 := L4{Port: svc.Port, Protocol: svc.Protocol}

	service, ok := v.Services[l4]

	if !ok {
		return ret
	}

	return service.Reals()
}

type Virtual struct {
	Metadata Metadata
	Healthy  bool
	Change   time.Time
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

func Load(c *config.Config) (*Healthchecks, error) {
	return _ConfHealthchecks(c, nil)
}

func (h *Healthchecks) Reload(c *config.Config) (*Healthchecks, error) {
	return _ConfHealthchecks(c, h)
}

func (h *Healthchecks) VLANs() map[uint16]string { return h.VLAN }
func (h *Healthchecks) VID(r IP4) uint16         { return h._VID[r] }

func _ConfHealthchecks(c *config.Config, old *Healthchecks) (*Healthchecks, error) {

	var hc Healthchecks

	hc.Virtual = map[IP4]Virtual{}

	hc.VLAN = c.VLANs

	for _vip, x := range c.VIPs {
		var vip IP4
		err := vip.UnmarshalText([]byte(_vip))
		if err != nil {
			return nil, err
		}

		v := Virtual{Services: map[L4]Service{}}

		for _l4, y := range x {
			var l4 L4
			err := l4.UnmarshalText([]byte(_l4))
			if err != nil {
				return nil, err
			}

			reals := map[IP4]Real{}
			backends := map[IPPort]Real{}

			for r, checks := range y.RIPs {
				rip := r.IP
				port := r.Port

				if port == 0 {
					port = l4.Port
				}

				checks.DefaultPort(port)

				real := Real{RIP: rip, Checks: checks, Port: port, Disabled: r.Disabled}

				reals[rip] = real
				backends[IPPort{IP: rip, Port: port}] = real
			}

			v.Services[l4] = Service{
				VIP:            vip,
				Port:           l4.Port,
				UDP:            l4.Protocol == types.UDP,
				Metadata:       Metadata{Name: y.Name, Description: y.Description},
				FallbackChecks: y.Local,
				Fallback:       y.Fallback,
				Minimum:        y.Need,
				Sticky:         y.Sticky,
				Backend:        backends,
				Scheduler:      y.Scheduler,
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
			//for rip, real := range s.Reals {
			//	real.VID = h._VID[rip]
			//	s.Reals[rip] = real
			//}
			for _, r := range s.reals() {
				r.VID = h._VID[r.RIP]
				s.UpdateReal(r)
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
	rips := map[IP4]IP4{}
	for _, v := range h.Virtual {
		for _, s := range v.Services {
			for _, r := range s.Reals() {
				rips[r.RIP] = r.RIP
			}
		}
	}
	return rips
}

func (h *Healthchecks) Tuples() map[[2]IP4]bool {
	n := map[[2]IP4]bool{}
	for vip, v := range h.Virtual {
		for _, s := range v.Services {
			//for rip, _ := range s.XReals {
			for k, _ := range s.reals() {
				n[[2]IP4{vip, k.IP}] = true
			}
		}
	}
	return n
}

func (h *Healthchecks) SetReal_(s SVC, r Real) {
	//rip := r.RIP
	l4 := L4{Port: s.Port, Protocol: s.Protocol}
	if _, ok := h.Virtual[s.VIP]; ok {
		if s, ok := h.Virtual[s.VIP].Services[l4]; ok {
			s.UpdateReal(r)
		}
	}
}

/********************************************************************************/

func (s *Service) reals() map[IPPort]Real {
	ret := map[IPPort]Real{}
	for k, r := range s.Backend {
		r.RIP = k.IP
		r.Port = k.Port
		ret[k] = r
	}
	return ret

}

func (s *Service) UpdateReal(r Real) {
	ip := IPPort{IP: r.RIP, Port: r.Port}
	if _, ok := s.Backend[ip]; ok {
		s.Backend[ip] = r
	}
}
