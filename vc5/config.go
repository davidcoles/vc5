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

package main

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
)

type HttpCheck struct {
	Path   string `json:"path"`
	Port   uint16 `json:"port"'`
	Expect uint32 `json:"expect"`
}

type TcpCheck struct {
	Port uint16 `json:"port"'`
}

type Checks struct {
	http  []HttpCheck `json:"http"`
	https []HttpCheck `json:"https"`
	tcp   []TcpCheck  `json:"tcp"`
}

type Real struct {
	Rip   IP4         `json:"rip"`
	Http  []HttpCheck `json:"http"`
	Https []HttpCheck `json:"https"`
	Tcp   []TcpCheck  `json:"tcp"`
	Nat   IP4
	VLan  uint16
	Src   IP4
}

type Service struct {
	Vip         IP4    `json:"vip"`
	Port        uint16 `json:"port"`
	Rip         []Real `json:"rip"`
	Need        uint   `json:"need"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Config struct {
	Multicast string            `json:"multicast"`
	Learn     uint16            `json:"learn"`
	Services  []Service         `json:"services"`
	Peers     []string          `json:"peers"`
	RHI       RHI               `json:"rhi"`
	VLans     map[string]uint16 `json:"vlans"`
}

type RHI struct {
	RouterId IP4      `json:"router_id"`
	ASNumber uint16   `json:"as_number"`
	Peers    []string `json:"peers"`
}

func LoadConfigFile(file string) (*Config, error) {
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

	fix_nat(&config)
	fix_vlan(&config)

	return &config, nil
}

func fix_vlan(config *Config) {
	for _, s := range config.Services {
		for r, R := range s.Rip {

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
	i := 0
	vr_to_n := make(map[[8]byte][4]byte)

	for _, s := range config.Services {
		for r, R := range s.Rip {
			vip := s.Vip
			rip := R.Rip
			vr := [8]byte{vip[0], vip[1], vip[2], vip[3], rip[0], rip[1], rip[2], rip[3]}

			if nat, ok := vr_to_n[vr]; ok {
				s.Rip[r].Nat = nat
			} else {
				nat = IP4{10, 1, byte((i >> 8) & 0xff), byte(i & 0xff)}
				s.Rip[r].Nat = nat
				vr_to_n[vr] = nat
				i++
			}
		}
	}
}
