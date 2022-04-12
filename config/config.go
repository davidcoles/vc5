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

	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type IP6 = types.IP6
type MAC = types.MAC
type L4 = types.L4

type HttpCheck struct {
	Path   string `json:"path"`
	Port   uint16 `json:"port"'`
	Expect uint32 `json:"expect"`
	Host   string `json:"host"`
}

type L4Check struct {
	Port uint16 `json:"port"'`
}
type Checks struct {
	Http  []HttpCheck `json:"http"`
	Https []HttpCheck `json:"https"`
	Tcp   []L4Check   `json:"tcp"`
	Syn   []L4Check   `json:"syn"`
	Dns   []L4Check   `json:"syn"`
}

type Real struct {
	Http  []HttpCheck `json:"http,omitempty"`
	Https []HttpCheck `json:"https,omitempty"`
	Tcp   []L4Check   `json:"tcp,omitempty"`
	Syn   []L4Check   `json:"syn,omitempty"`
	Dns   []L4Check   `json:"dns,omitempty"`

	Rip IP4 `json:"rip"`
	Nat IP4 `json:"nat"`
	//_Info Info   `json:"info"`
	Index uint16 `json:"index"`
}

type Service struct {
	Rip         map[IP4]Real `json:"rips"`
	Need        uint         `json:"need"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	LeastConns  bool         `json:"leastconns"`
	Sticky      bool         `json:"sticky"`
}

type VR struct {
	VIP IP4
	RIP IP4
}

func (v VR) MarshalText() ([]byte, error) {
	return []byte(v.string()), nil
}
func (v VR) string() string {
	return v.VIP.String() + ":" + v.RIP.String()
}

type NI struct {
	NAT  IP4
	Info Info
}

type Info struct {
	Index  uint16
	Iface  net.Interface
	VLAN   uint16
	Source IP4
	IPNet  net.IPNet
	MAC    MAC
}

type RHI struct {
	ASNumber uint16   `json:"as_number"`
	HoldTime uint16   `json:"hold_time"`
	Peers    []string `json:"peers"`
}

type Config struct {
	Multicast string                 `json:"multicast"`
	Webserver string                 `json:"webserver"`
	Learn     uint16                 `json:"learn"`
	RHI       RHI                    `json:"rhi"`
	VIPs      map[IP4]map[L4]Service `json:"vips"`
	VLANs     map[uint16]string      `json:"vlans"`

	Address    IP4           `json:"-"`
	_IfName    string        `json:"-"`
	_Hardware  MAC           `json:"-"`
	_IfIndex   int           `json:"-"`
	_Interface net.Interface `json:"-"`
	Real       map[IP4]Info  `json:"real"`
	NAT        map[VR]NI     `json:"nat"`

	_nats map[VR]uint16
	_real map[IP4]uint16
	_vlan map[uint16]Info
}

func (c *Config) vlan_mode() bool {
	if len(c._vlan) > 0 {
		return true
	}

	return false
}

func (old *Config) ReloadConfiguration(file string) (*Config, error) {
	return loadConfiguration(file, old._IfName, old.Address, old)
}

func LoadConfiguration(file string, ifname string, src IP4) (*Config, error) {
	return loadConfiguration(file, ifname, src, nil)
}

func (c *Config) find_vlan(ip IP4) uint16 {
	for id, info := range c._vlan {
		i := []byte{ip[0], ip[1], ip[2], ip[3]}
		if info.IPNet.Contains(i) {
			return id
		}
	}
	return 0
}

func fix_vlans(c *Config) error {
	vlans := c.VLANs
	c._vlan = make(map[uint16]Info)

	for k, v := range vlans {

		if k == 0 || k >= 0xfff {
			return errors.New(fmt.Sprint("Invalid VLAN (outside range 1-4094): ", k))
		}

		ifname := fmt.Sprintf("vlan%d", k)

		_, vnet, err := net.ParseCIDR(v)
		if err != nil {
			return errors.New(fmt.Sprint("VLAN ", k, " CIDR address invalid: ", v))
		}

		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			return errors.New(fmt.Sprint("VLAN ", k, " has no matching interface: ", ifname))
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var hasip bool

		for _, a := range addrs {
			ip, ipnet, err := net.ParseCIDR(a.String())
			if err == nil && ipnet.String() == vnet.String() {
				ip4 := ip.To4()
				hasip = true

				src := IP4{ip4[0], ip4[1], ip4[2], ip4[3]}
				var mac MAC
				copy(mac[:], iface.HardwareAddr)
				info := Info{Index: 0, Iface: *iface, VLAN: k, Source: src, IPNet: *ipnet, MAC: mac}
				c._vlan[k] = info
			}
		}

		if !hasip {
			return errors.New(fmt.Sprint("VLAN ", k, " has no matching IP for ", vnet.String(), " on ", ifname))
		}
	}

	return nil
}

func fix_nat(new, old *Config) error {

	natify := func(i uint16) IP4 {
		i += 4
		return IP4{10, 255, byte((i >> 8) & 0xff), byte(i & 0xff)}
	}

	type idx struct {
		n uint16
		u bool
	}

	newi := func(m map[VR]idx) (uint16, error) {
		n := make(map[uint16]bool)
		for _, v := range m {
			n[v.n] = true
		}

		var i uint16 = 1
	check_exists:
		if _, ok := n[i]; ok {
			i++
			if i > 65000 {
				return 0, errors.New("Only max 65000 NAT slots allowed currently")
			}
			goto check_exists
		}

		return i, nil
	}

	nats := make(map[VR]idx)

	if old != nil {
		for k, v := range old._nats {
			nats[k] = idx{n: v, u: false}
		}
	}

	for vip, v := range new.VIPs {
		for l4, s := range v {
			for rip, _ := range s.Rip {

				var i uint16

				viprip := VR{VIP: vip, RIP: rip}

				if v, ok := nats[viprip]; ok {
					i = v.n
					v.u = true
					nats[viprip] = v
				} else {
					var e error
					i, e = newi(nats)
					if e != nil {
						return e
					}
					nats[viprip] = idx{n: i, u: true}
				}

				obj := new.VIPs[vip][l4].Rip[rip]
				obj.Nat = natify(i)
				new.VIPs[vip][l4].Rip[rip] = obj
			}
		}
	}

	new._nats = make(map[VR]uint16)
	new.NAT = make(map[VR]NI)

	for k, v := range nats {
		if v.u {
			new._nats[k] = v.n
			info := new.Real[k.RIP]
			nat := natify(v.n)
			new.NAT[k] = NI{NAT: nat, Info: info}
		}
	}

	return nil
}

func fix_idx(new, old *Config) error {
	type idx struct {
		n uint16
		u bool
	}

	newi := func(m map[IP4]idx) (uint16, error) {
		n := make(map[uint16]bool)
		for _, v := range m {
			n[v.n] = true
		}

		var i uint16 = 1
	check_exists:
		if _, ok := n[i]; ok {
			i++
			if i > 255 {
				return 0, errors.New("Only max 255 real servers allowed currently")
			}
			goto check_exists
		}

		return i, nil
	}

	reals := make(map[IP4]idx)

	if old != nil {
		for k, v := range old._real {
			reals[k] = idx{n: v, u: false}
		}
	}

	for vip, v := range new.VIPs {
		for l4, s := range v {
			for rip, real := range s.Rip {

				var i uint16

				if v, ok := reals[rip]; ok {
					i = v.n
					v.u = true
					reals[rip] = v
				} else {
					var e error
					i, e = newi(reals)
					if e != nil {
						return e
					}
					reals[rip] = idx{n: i, u: true}
				}

				real.Index = i
				new.VIPs[vip][l4].Rip[rip] = real
			}
		}
	}

	new._real = make(map[IP4]uint16)

	for k, v := range reals {
		if v.u {
			new._real[k] = v.n
			info := new.Real[k]
			info.Index = v.n
			new.Real[k] = info
		}
	}
	return nil
}

func fix_reals(c *Config) error {

	c.Real = make(map[IP4]Info)

	for _, vip := range c.VIPs {
		for _, service := range vip {
			for rip, _ := range service.Rip {

				var info Info

				if _, ok := c.Real[rip]; ok {
					continue
				}

				if c.vlan_mode() {
					vlan := c.find_vlan(rip)
					if vlan == 0 {
						return errors.New("Real " + rip.String() + " is not in a VLAN")
					}
					info = c._vlan[vlan]
				} else {
					info.Source = c.Address
					info.Iface = c._Interface
					info.VLAN = 0
				}

				c.Real[rip] = info
			}
		}
	}

	return nil
}

func fix_services(c *Config) error {

	for vip, m := range c.VIPs {
		for l4, service := range m {
			for k, r := range service.Rip {
				r.Rip = k
				//r._Info = c.Real[r.Rip]
				service.Rip[k] = r
			}
			c.VIPs[vip][l4] = service
		}
	}

	return nil
}

func loadConfigFile(file string) (*Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var config Config

	err = json.Unmarshal(b, &(config))
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func loadConfiguration(file string, ifname string, src IP4, old *Config) (*Config, error) {

	config, err := loadConfigFile(file)
	if err != nil {
		return nil, err
	}

	if config.RHI.HoldTime == 0 {
		config.RHI.HoldTime = 5
	}

	err = fix_vlans(config)
	if err != nil {
		return nil, err
	}

	if old != nil && old.vlan_mode() != config.vlan_mode() {
		return nil, errors.New("Can't dynamically change VLAN mode, sorry.")
	}

	if config.vlan_mode() {
		vlan := config.find_vlan(src)

		if vlan == 0 {
			return nil, errors.New("Bind IP is not contained in any VLAN: " + src.String())
		}

		info := config._vlan[vlan]

		config._IfName = info.Iface.Name
		config.Address = src

		copy(config._Hardware[:], info.Iface.HardwareAddr[:])
		config._IfIndex = info.Iface.Index
		config._Interface = info.Iface

	} else {

		config._IfName = ifname
		config.Address = src

		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			return nil, err
		}

		copy(config._Hardware[:], iface.HardwareAddr[:])
		config._IfIndex = iface.Index
		config._Interface = *iface

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		var found bool

		for _, addr := range addrs {
			ipaddr, ipnet, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, err
			}

			fmt.Println("DEBUG ", addr, ipaddr, ipnet, iface.Index)

			if ipaddr.String() == src.String() {
				found = true
			}
		}

		if !found {
			return nil, errors.New("Couldn't find IP " + src.String() + " on interface " + ifname)
		}
	}

	err = fix_reals(config)
	if err != nil {
		return nil, err
	}

	err = fix_services(config)
	if err != nil {
		return nil, err
	}

	err = fix_nat(config, old)
	if err != nil {
		return nil, err
	}

	err = fix_idx(config, old)
	if err != nil {
		return nil, err
	}

	return config, nil
}
