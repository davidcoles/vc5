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
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/davidcoles/vc5/config"
	"github.com/davidcoles/vc5/types"
)

const UDP = 17
const TCP = 6

type IP4 = types.IP4
type MAC = types.MAC
type NET = types.NET
type L4 = types.L4

type IPPort = types.IPPort
type Protocol uint8

func (p Protocol) Old() types.Protocol {
	if p == 17 {
		return types.UDP
	}

	return types.TCP
}

func (p Protocol) String() string {
	if p == 17 {
		return "UDP"
	}

	return "TCP"
}

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

	Disabled bool
	Checks   []Check

	MAC    MAC
	VID    uint16
	XProbe Probe
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
type Healthchecks struct {
	Virtual map[IP4]Virtual `json:",omitempty"`
	_VID    map[IP4]uint16  `json:",omitempty"`
	VLAN    map[uint16]string
}

type Destination struct {
	Address IP4
	Port    uint16
	Up      bool

	Disabled   bool
	Healthy    bool
	Time       time.Time
	Duration   time.Duration
	Diagnostic string
}

func (r *Real) Destination() Destination {
	p := r.Probe()
	return Destination{
		Address: r.RIP,
		Port:    r.Port,
		Up:      p.Passed && !r.Disabled,

		Disabled:   r.Disabled,
		Healthy:    p.Passed,
		Time:       p.Time,
		Duration:   p.Duration,
		Diagnostic: p.Message,
	}
}

func (h *Healthchecks) Destinations(svc Serv) ([]Destination, error) {
	vip := svc.Address
	l4 := L4{Port: svc.Port, Protocol: svc.Protocol == UDP}

	v, ok := h.Virtual[vip]

	if !ok {
		return nil, errors.New("Unknown service")
	}

	s, ok := v.Services[l4]

	if !ok {
		return nil, errors.New("Unknown service")
	}

	return s.Destinations(), nil
}

func (s *Service) Destinations() []Destination {
	var ret []Destination
	for _, r := range s.reals() {
		ret = append(ret, r.Destination())
	}
	return ret
}

type SVC struct {
	VIP      IP4
	Port     uint16
	Protocol Protocol
}

func (s *SVC) L4() L4 {
	return L4{Port: s.Port, Protocol: s.Protocol.Old()}
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

func (h *Healthchecks) Services__() map[SVC]Service {
	ret := map[SVC]Service{}

	for vip, v := range h.Virtual {
		for l4, s := range v.Services {
			f := SVC{VIP: vip, Port: l4.Port, Protocol: Protocol(l4.Protocol.Number())}

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
			ret = append(ret, SVC{VIP: vip, Port: l4.Port, Protocol: Protocol(l4.Protocol.Number())})
		}
	}

	return ret
}

type Serv struct {
	Address   IP4
	Port      uint16
	Protocol  uint8
	Scheduler types.Scheduler
	Sticky    bool
}

func (h *Healthchecks) Services() ([]Serv, error) {
	var ret []Serv

	for vip, v := range h.Virtual {
		for l4, s := range v.Services {
			ret = append(ret, Serv{
				Address:   vip,
				Port:      l4.Port,
				Protocol:  l4.Protocol.Number(),
				Scheduler: s.Scheduler,
				Sticky:    s.Sticky,
			})
		}
	}

	return ret, nil
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

	l4 := L4{Port: svc.Port, Protocol: svc.Protocol.Old()}

	service, ok := v.Services[l4]

	if !ok {
		return ret
	}

	return service.Reals()
}

type vr [2]IP4

func (v vr) MarshalText() ([]byte, error) {
	return []byte(v[0].String() + "/" + v[1].String()), nil
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

	dsr := true

	for s, svc := range c.Services {

		_, ok := hc.Virtual[s.IP]

		if !ok {
			hc.Virtual[s.IP] = Virtual{Services: map[L4]Service{}}
		}

		backends := map[IPPort]Real{}

		for d, dest := range svc.Reals {

			port := d.Port

			if port == 0 {
				port = s.Port
			}

			for i, c := range dest.Checks {
				if c.Port == 0 {
					c.Port = port
				}

				dest.Checks[i] = c
			}

			if dsr && port != s.Port {
				return nil, errors.New(
					fmt.Sprintf("Destination port does not match service port in DSR service: %s %s:%d->%s:%d",
						Protocol(s.Protocol), s.IP, s.Port, d.IP, port))
			}

			backends[IPPort{IP: d.IP, Port: port}] = Real{RIP: d.IP, Checks: dest.Checks, Port: port, Disabled: dest.Disabled}
		}

		l4 := L4{Port: s.Port, Protocol: s.Protocol == 17}

		hc.Virtual[s.IP].Services[l4] = Service{
			VIP:       s.IP,
			Port:      l4.Port,
			UDP:       l4.Protocol == types.UDP,
			Metadata:  Metadata{Name: svc.Name, Description: svc.Description},
			Minimum:   svc.Need,
			Scheduler: svc.Scheduler,
			Sticky:    svc.Sticky,
			Backend:   backends,
		}
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
			for k, _ := range s.reals() {
				n[[2]IP4{vip, k.IP}] = true
			}
		}
	}
	return n
}

func (h *Healthchecks) SetReal_(s SVC, r Real) {
	l4 := L4{Port: s.Port, Protocol: s.Protocol.Old()}
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
