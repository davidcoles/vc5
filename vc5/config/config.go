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

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"

	"vc5/types"
)

type IP4 = types.IP4
type IP6 = types.IP6
type MAC = types.MAC
type L4 = types.L4

const TCP = types.TCP
const UDP = types.UDP

type HttpCheck struct {
	Path   string `json:"path"`
	Port   uint16 `json:"port"'`
	Expect uint32 `json:"expect"`
	Host   string `json:"host"`
}

type TcpCheck struct {
	Port uint16 `json:"port"'`
}

type SynCheck struct {
	Port uint16 `json:"port"'`
}

type Checks struct {
	Http  []HttpCheck `json:"http"`
	Https []HttpCheck `json:"https"`
	Tcp   []TcpCheck  `json:"tcp"`
	Syn   []SynCheck  `json:"syn"`
}

type Real struct {
	Rip     IP4         `json:"rip"`
	Http    []HttpCheck `json:"http,omitempty"`
	Https   []HttpCheck `json:"https,omitempty"`
	Tcp     []TcpCheck  `json:"tcp,omitempty"`
	Syn     []SynCheck  `json:"syn,omitempty"`
	Nat     IP4         `json:"nat"`
	VLAN    uint16      `json:"vlan,omitempty"`
	Src     IP4         `json:"src"`
	Idx     uint16
	Iface   string
	Port    uint16
	Vip     IP4
	Udp     bool
	IfIndex int
	IfMAC   MAC
}

func (r *Real) Service() types.ThreeTuple {
	if r.Udp {
		return types.ThreeTuple{r.Vip, r.Port, UDP}
	}
	return types.ThreeTuple{r.Vip, r.Port, TCP}
}

type Service struct {
	Vip         IP4             `json:"vip"`
	Port        uint16          `json:"port"`
	Rip         map[string]Real `json:"rip"`
	Need        uint            `json:"need"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	LeastConns  bool            `json:"leastconns"`
	Udp         bool            `json:"udp"`
}

func (s *Service) String() string {
	t := s.Tuple()
	return t.String()
}

func (s *Service) L4() types.L4 {
	return L4{s.Port, s.Udp}
}

func (s *Service) Tuple() types.ThreeTuple {
	if s.Udp {
		return types.ThreeTuple{s.Vip, s.Port, UDP}
	}
	return types.ThreeTuple{s.Vip, s.Port, TCP}
}
func (s *Service) Protocol() types.Protocol {
	if s.Udp {
		return types.UDP
	}
	return types.TCP
}

type Service_ struct {
	Real        map[string]Real `json:"rips"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	LeastConns  bool            `json:"leastconns"`
	Need        uint            `json:"need"`
}

type Config struct {
	Multicast string                         `json:"multicast"`
	Webserver string                         `json:"webserver"`
	Learn     uint16                         `json:"learn"`
	VIPs      map[IP4]map[L4]Service         `json:"-"`
	Vips      map[string]map[string]Service_ `json:"vips"`
	RHI       RHI                            `json:"rhi"`
	VLANs     map[uint16]string              `json:"vlans"`

	Address   IP4
	Interface string
	Hardware  MAC

	Reals map[IP4]uint16     `json:"-"`
	Nats  map[[8]byte]uint16 `json:"-"`

	Out map[string]map[string]Service `json:"out"` // for visualisation/debug
}

type RHI struct {
	RouterId IP4      `json:"router_id"`
	ASNumber uint16   `json:"as_number"`
	Peers    []string `json:"peers"`
}

func (old *Config) ReloadConfiguration(file string) (*Config, error) {
	new, err := LoadConfigFile_(file)
	if err != nil {
		return nil, err
	}

	new.Interface = old.Interface
	new.Address = old.Address
	new.Hardware = old.Hardware
	new.RHI.RouterId = old.RHI.RouterId

	err = fix_new(new)
	if err != nil {
		return nil, err
	}

	fix_nat2(new, old)
	fix_idx(new, old)
	//fix_vlan(new)
	//fix_service(new)

	return new, nil
}
func LoadConfiguration(file string, iface string, src IP4) (*Config, error) {
	config, err := LoadConfigFile_(file)
	if err != nil {
		return nil, err
	}

	config.RHI.RouterId = src

	config.Interface = iface
	config.Address = src

	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	copy(config.Hardware[:], i.HardwareAddr[:])
	//r.IfIndex = iface.Index

	err = fix_new(config)
	if err != nil {
		return nil, err
	}

	fix_nat2(config, nil)
	fix_idx(config, nil)
	//fix_vlan(config)
	//fix_service(config)

	return config, nil
}

func LoadConfigFile_(file string) (*Config, error) {
	jf, err := os.Open(file)

	if err != nil {
		return nil, err
	}
	defer jf.Close()

	bs, _ := ioutil.ReadAll(jf)

	var config Config
	//err = json.Unmarshal(bs, &(config.Services_))
	err = json.Unmarshal(bs, &(config))

	if err != nil {
		return nil, err
	}

	jf.Close()

	return &config, nil
}

//func parseIP(ip string) ([4]byte, bool) {
func parseIP(ip string) (IP4, bool) {
	var addr [4]byte
	re := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)\.(\d+)$`)
	m := re.FindStringSubmatch(ip)
	if len(m) != 5 {
		return addr, false
	}
	for n, _ := range addr {
		a, err := strconv.ParseInt(m[n+1], 10, 9)
		if err != nil || a < 0 || a > 255 {
			return addr, false
		}
		addr[n] = byte(a)
	}
	return IP4(addr), true
}

func fix_new(c *Config) error {

	c.VIPs = make(map[IP4]map[L4]Service)
	c.Out = make(map[string]map[string]Service)

	for i, m := range c.Vips {

		ip, ok := parseIP(i)
		if !ok {
			return errors.New("VIP is not a valid IP address: " + i)
		}

		vip := IP4{ip[0], ip[1], ip[2], ip[3]}

		c.VIPs[vip] = make(map[L4]Service)
		c.Out[vip.String()] = make(map[string]Service)

		for pp, s_ := range m {

			re := regexp.MustCompile(`^(udp|tcp):([1-9][0-9]*)$`)
			ma := re.FindStringSubmatch(pp)
			if len(ma) != 3 {
				return errors.New("Service is not of the form (tcp|udp):<port> : " + pp)
			}
			port, err := strconv.Atoi(ma[2])
			if err != nil || port < 1 || port > 65535 {
				return errors.New("Invalid port number : " + pp)
			}

			var udp bool
			if ma[1] == "udp" {
				udp = true
			}

			var s Service
			s.Rip = make(map[string]Real)

			for k, v := range s_.Real {
				ip, ok := parseIP(k)
				if !ok {
					return errors.New("RIP '" + k + "' incorrect")
				}
				v.Rip = ip
				s.Rip[ip.String()] = v
				//s.Rip[v.Rip.String()] = v
			}

			s.Name = s_.Name
			s.Description = s_.Description
			s.Need = s_.Need
			s.LeastConns = s_.LeastConns

			s.Udp = udp
			s.Vip = vip
			s.Port = uint16(port)

			for k, r := range s.Rip {
				rip := r.Rip
				//vr := [8]byte{vip[0], vip[1], vip[2], vip[3], rip[0], rip[1], rip[2], rip[3]}

				r.Vip = vip
				//r.Nat = natify(c.Nats[vr])
				r.Port = uint16(port)
				r.Udp = udp
				//r.Idx = c.Reals[rip]

				r.Src = c.Address
				r.Iface = c.Interface
				//r.IfMAC = c.Hardware

				iface, err := net.InterfaceByName(c.Interface)
				if err != nil {
					return err
				}
				r.IfIndex = iface.Index
				copy(r.IfMAC[:], iface.HardwareAddr[:])

				for vlan, cidr := range c.VLANs {
					ip, ipnet, err := net.ParseCIDR(cidr)
					if err != nil {
						return err
					}

					if ipnet.Contains(rip[:]) {
						device := fmt.Sprintf("vlan%d", vlan)
						iface, err := net.InterfaceByName(device)

						if err != nil {
							return err
						}

						r.Src = IP4{ip[12], ip[13], ip[14], ip[15]}
						r.Iface = device
						r.VLAN = vlan
						r.IfIndex = iface.Index
						copy(r.IfMAC[:], iface.HardwareAddr[:])
					}
				}

				s.Rip[k] = r
			}

			//v := IP4{vip[0], vip[1], vip[2], vip[3]}
			l4 := L4{Port: uint16(port), Udp: udp}
			//c.Vips[v.String()][l4.String()] = s
			c.VIPs[vip][l4] = s
			c.Out[vip.String()][l4.String()] = s
		}
	}

	c.Vips = nil

	return nil
}

func fix_nat2(new, old *Config) {
	//fmt.Println(new.Vips)

	natify := func(i uint16) IP4 {
		return IP4{10, 1, byte((i >> 8) & 0xff), byte(i & 0xff)}
	}

	type idx struct {
		n uint16
		u bool
	}

	newi := func(m map[[8]byte]idx) uint16 {
		n := make(map[uint16]bool)
		for _, v := range m {
			n[v.n] = true
		}

		var i uint16 = 1
	check_exists:
		if _, ok := n[i]; ok {
			i++
			if i > 65000 {
				panic("i > 65000")
			}
			goto check_exists
		}

		return i
	}

	nats := make(map[[8]byte]idx)

	if old != nil {
		for k, v := range old.Nats {
			nats[k] = idx{n: v, u: false}
		}
	}

	for _, v := range new.VIPs {
		for l4, s := range v {
			for k, r := range s.Rip {
				vip := s.Vip
				rip := r.Rip

				viprip := [8]byte{vip[0], vip[1], vip[2], vip[3], rip[0], rip[1], rip[2], rip[3]}

				var i uint16

				if v, ok := nats[viprip]; ok {
					//s.Rip[k].Nat = natify(v.n)
					i = v.n
					v.u = true
					nats[viprip] = v
				} else {
					i = newi(nats)
					//s.Rip[k].Nat = natify(i)
					nats[viprip] = idx{n: i, u: true}
				}

				obj := new.VIPs[vip][l4].Rip[k]
				obj.Nat = natify(i)
				new.VIPs[vip][l4].Rip[k] = obj

				//new.VIPs[vip][l4].Rip[k].Nat = natify(i)

			}
		}
	}

	new.Nats = make(map[[8]byte]uint16)

	for k, v := range nats {
		if v.u {
			new.Nats[k] = v.n
		}
	}
}

func fix_idx(new, old *Config) {
	type idx struct {
		n uint16
		u bool
	}

	newi := func(m map[IP4]idx) uint16 {
		n := make(map[uint16]bool)
		for _, v := range m {
			n[v.n] = true
		}

		var i uint16 = 1
	check_exists:
		if _, ok := n[i]; ok {
			i++
			if i > 65000 {
				panic("i > 65000")
			}
			goto check_exists
		}

		return i
	}

	reals := make(map[IP4]idx)

	if old != nil {
		for k, v := range old.Reals {
			reals[k] = idx{n: v, u: false}
		}
	}

	for _, v := range new.VIPs {
		for l4, s := range v {
			for k, r := range s.Rip {
				rip := r.Rip
				vip := r.Vip

				var i uint16

				if v, ok := reals[rip]; ok {
					//s.Rip[k].Idx = v.n
					i = v.n
					v.u = true
					reals[rip] = v
				} else {
					i = newi(reals)
					//s.Rip[k].Idx = i
					reals[rip] = idx{n: i, u: true}
				}

				obj := new.VIPs[vip][l4].Rip[k]
				obj.Idx = i
				new.VIPs[vip][l4].Rip[k] = obj
				//new.VIPs[vip][l4].Rip[k].Idx = i
			}
		}
	}

	new.Reals = make(map[IP4]uint16)

	for k, v := range reals {
		if v.u {
			new.Reals[k] = v.n
		}
	}
}
