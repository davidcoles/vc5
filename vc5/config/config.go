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
	Rip   IP4         `json:"rip"`
	Http  []HttpCheck `json:"http,omitempty"`
	Https []HttpCheck `json:"https,omitempty"`
	Tcp   []TcpCheck  `json:"tcp,omitempty"`
	Syn   []SynCheck  `json:"syn,omitempty"`
	Nat   IP4         `json:"nat"`
	VLan  uint16      `json:"vlan,omitempty"`
	Src   IP4         `json:"src"`
	Idx   uint16
	Iface string
	Port  uint16
	Vip   IP4
}

type Service struct {
	Vip         IP4    `json:"vip"`
	Port        uint16 `json:"port"`
	Rip         []Real `json:"rip"`
	Need        uint   `json:"need"`
	Name        string `json:"name"`
	Description string `json:"description"`
	LeastConns  bool   `json:"leastconns"`
}

type Config struct {
	Multicast string            `json:"multicast"`
	Webserver string            `json:"webserver"`
	Learn     uint16            `json:"learn"`
	Services  []Service         `json:"services"`
	RHI       RHI               `json:"rhi"`
	VLans     map[string]uint16 `json:"vlans"`
	Reals     map[IP4]uint16
	Nats      map[[8]byte]uint16
}

type RHI struct {
	RouterId IP4      `json:"router_id"`
	ASNumber uint16   `json:"as_number"`
	Peers    []string `json:"peers"`
}

func (old *Config) LoadNewConfigFile(file string, iface string, src IP4) (*Config, error) {
	new, err := LoadConfigFile_(file)
	if err != nil {
		return nil, err
	}

	fix_nats(new, old)
	fix_idx(new, old)
	fix_vlan(new, iface, src)
	fix_service(new)

	return new, nil
}
func LoadConfigFile(file string, iface string, src IP4) (*Config, error) {
	config, err := LoadConfigFile_(file)
	if err != nil {
		return nil, err
	}

	fix_nats(config, nil)
	fix_idx(config, nil)

	fix_vlan(config, iface, src)
	fix_service(config)

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
	//err = json.Unmarshal(bs, &(config.Services))
	err = json.Unmarshal(bs, &(config))

	if err != nil {
		return nil, err
	}

	jf.Close()

	return &config, nil
}

func fix_service(config *Config) {
	for _, s := range config.Services {
		for r, _ := range s.Rip {
			s.Rip[r].Port = s.Port
			s.Rip[r].Vip = s.Vip
		}
	}
}

func fix_vlan(config *Config, iface string, src IP4) {
	for _, s := range config.Services {
		for r, R := range s.Rip {
			s.Rip[r].Src = src
			s.Rip[r].Iface = iface

			for k, v := range config.VLans {
				i, n, e := net.ParseCIDR(k)
				if e == nil {
					//i := net.ParseIP(R.Rip.String())
					if n.Contains(net.ParseIP(R.Rip.String())) {
						s.Rip[r].VLan = v
						p, _ := parseIP(i.String())
						s.Rip[r].Src[0] = p[0]
						s.Rip[r].Src[1] = p[1]
						s.Rip[r].Src[2] = p[2]
						s.Rip[r].Src[3] = p[3]
					}
				}
			}
		}
	}
}

func fix_nat(config *Config) {
	// fix up nat addresses - assign a unique nat address for each vip/nat tuple
	var i uint16
	config.Reals = make(map[IP4]uint16)

	natify := func(i uint16) IP4 {
		return IP4{10, 1, byte((i >> 8) & 0xff), byte(i & 0xff)}
	}
	//vr_to_n := make(map[[8]byte][4]byte)
	vr_to_i := make(map[[8]byte]uint16)

	for _, s := range config.Services {
		for r, R := range s.Rip {
			vip := s.Vip
			rip := R.Rip
			vr := [8]byte{vip[0], vip[1], vip[2], vip[3], rip[0], rip[1], rip[2], rip[3]}

			if n, ok := vr_to_i[vr]; ok {
				s.Rip[r].Nat = natify(n)
				s.Rip[r].Idx = n + 1
			} else {
				s.Rip[r].Nat = natify(i)
				s.Rip[r].Idx = i + 1
				vr_to_i[vr] = i
				i++
			}

			if _, ok := config.Reals[rip]; !ok {
				config.Reals[rip] = uint16(len(config.Reals)) + 1
			}
		}
	}

}

func parseIP(ip string) ([4]byte, bool) {
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
	return addr, true
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
		// do some stuff
		for k, v := range old.Reals {
			reals[k] = idx{n: v, u: false}
			//if v >= i {
			//	i = v + 1
			//}
		}
	}

	for _, s := range new.Services {
		for k, r := range s.Rip {
			rip := r.Rip

			if v, ok := reals[rip]; ok {
				s.Rip[k].Idx = v.n
				v.u = true
				reals[rip] = v
			} else {
				i := newi(reals)
				s.Rip[k].Idx = i
				reals[rip] = idx{n: i, u: true}
				fmt.Println("XXXX", rip, i)
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

func fix_nats(new, old *Config) {
	// fix up nat addresses - assign a unique nat address for each vip/nat tuple
	var i uint16 = 1

	natify := func(i uint16) IP4 {
		return IP4{10, 1, byte((i >> 8) & 0xff), byte(i & 0xff)}
	}

	if new != nil {

	}

	nats := make(map[[8]byte]uint16)

	for _, s := range new.Services {
		for r, R := range s.Rip {
			vip := s.Vip
			rip := R.Rip
			viprip := [8]byte{vip[0], vip[1], vip[2], vip[3], rip[0], rip[1], rip[2], rip[3]}

			if n, ok := nats[viprip]; ok {
				s.Rip[r].Nat = natify(n)
			} else {
				s.Rip[r].Nat = natify(i)
				nats[viprip] = i
				i++
			}
		}
	}

	new.Nats = nats
}
