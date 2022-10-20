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

type Real struct {
	Http  []HttpCheck `json:"http,omitempty"`
	Https []HttpCheck `json:"https,omitempty"`
	Tcp   []L4Check   `json:"tcp,omitempty"`
	Syn   []L4Check   `json:"syn,omitempty"`
	Dns   []L4Check   `json:"dns,omitempty"`
	Rip   IP4         `json:"rip"`
	Nat   IP4         `json:"nat"`
	Index uint16      `json:"index"`
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
	Source IP4
	VLAN   uint16
	Iface  net.Interface
	IPNet  net.IPNet
}

func (i *Info) HWAddr() MAC {
	var mac MAC
	copy(mac[:], i.Iface.HardwareAddr)
	return mac
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

type RHI struct {
	ASNumber     uint16      `json:"as_number"`
	HoldTime     uint16      `json:"hold_time"`
	Peers        []string    `json:"peers"`
	Communities_ []community `json:"communities"`
}

func (r *RHI) Communities() []uint32 {
	var c []uint32
	for _, v := range r.Communities_ {
		c = append(c, uint32(v))
	}
	return c
}

type RI struct {
	Index uint16
	VLAN  uint16
}

type Config struct {
	Multicast string                 `json:"multicast"`
	Webserver string                 `json:"webserver"`
	Learn     uint16                 `json:"learn"`
	RHI       RHI                    `json:"rhi"`
	VIPs      map[IP4]map[L4]Service `json:"vips"`
	VLANs     map[uint16]string      `json:"vlans"`

	// calculated from json ...
	Reals map[IP4]RI `json:"reals"`
	NAT   map[VR]NI  `json:"nat"`

	// passed by application
	Address    IP4           `json:"-"`
	_Interface net.Interface `json:"-"`

	// internal use only - calculated
	_nats map[VR]uint16
	_real map[IP4]uint16
	_vlan map[uint16]Info
}

func LoadConfiguration(file string, ifname string, src IP4) (*Config, error) {
	return loadConfiguration(file, ifname, src, nil)
}

func (old *Config) ReloadConfiguration(file string) (*Config, error) {
	return loadConfiguration(file, old._Interface.Name, old.Address, old)
}

func (c *Config) vlan_mode() bool {
	if len(c._vlan) > 0 {
		return true
	}

	return false
}

func (c *Config) find_vlan(ip IP4) uint16 {
	for vlan_id, info := range c._vlan {
		if info.IPNet.Contains([]byte{ip[0], ip[1], ip[2], ip[3]}) {
			return vlan_id
		}
	}
	return 0
}

func fix_vlans(c *Config) error {

	c._vlan = make(map[uint16]Info)

	for vlan_id, cidr := range c.VLANs {

		if vlan_id == 0 || vlan_id > 4094 {
			return errors.New(fmt.Sprint("Invalid VLAN (outside range 1-4094): ", vlan_id))
		}

		ifname := fmt.Sprintf("vlan%d", vlan_id)

		_, vnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return errors.New(fmt.Sprint("VLAN ", vlan_id, " CIDR address invalid: ", cidr))
		}

		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			return errors.New(fmt.Sprint("VLAN ", vlan_id, " has no matching interface: ", ifname))
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return errors.New(fmt.Sprint("VLAN ", vlan_id, " has no addresses: ", ifname))
		}

		var hasip bool

		for _, a := range addrs {
			ip, ipnet, err := net.ParseCIDR(a.String())
			if err == nil && ipnet.String() == vnet.String() {
				ip4 := ip.To4()
				src := IP4{ip4[0], ip4[1], ip4[2], ip4[3]}
				info := Info{Iface: *iface, VLAN: vlan_id, Source: src, IPNet: *ipnet}
				c._vlan[vlan_id] = info
				hasip = true
			}
		}

		if !hasip {
			return errors.New(fmt.Sprint("VLAN ", vlan_id, " has no matching IP for ", vnet.String(), " on ", ifname))
		}
	}

	return nil
}

func fix_nat(new, old *Config) error {

	// gather nework deails for the reals
	reals, err := real_info(new)
	if err != nil {
		return err
	}

	natify := func(i uint16) IP4 {
		i += 4
		return IP4{10, 255, byte((i >> 8) & 0xff), byte(i & 0xff)}
	}

	type idx struct {
		n uint16
		u bool
	}

	new_index := func(m map[VR]idx) (uint16, error) {
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

	for vip, services := range new.VIPs {
		for l4, service := range services {
			for rip, _ := range service.Rip {

				var i uint16

				viprip := VR{VIP: vip, RIP: rip}

				if v, ok := nats[viprip]; ok {
					i = v.n
					v.u = true
					nats[viprip] = v
				} else {
					var e error
					i, e = new_index(nats)
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
			info := reals[k.RIP]
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

	//rips := make(map[IP4]bool)
	reals := make(map[IP4]idx)
	used := make(map[uint16]bool)

	var n uint16 = 1
	new_index := func() (uint16, error) {
		for ; n < 256; n++ {
			if _, ok := used[n]; !ok {
				used[n] = true // mark index# as used
				return n, nil
			}
		}
		return 0, errors.New("Only max 255 real servers allowed currently")
	}

	//for vip, services := range new.VIPs {
	//	for l4, service := range services {
	//		for rip, _ := range service.Rip {
	//			rips[rip] = true
	//		}
	//	}
	//}

	if old != nil {
		for k, v := range old._real {
			reals[k] = idx{n: v, u: false}
			used[v] = true // mark index# as used
		}
	}

	for vip, services := range new.VIPs {
		for l4, service := range services {
			for rip, real := range service.Rip {

				var i uint16

				if v, ok := reals[rip]; ok {
					i = v.n
					v.u = true
					reals[rip] = v
				} else {
					var e error

					i, e = new_index()

					if e != nil {
						return e
					}
					reals[rip] = idx{n: i, u: true}
				}

				real.Index = i
				real.Rip = rip
				new.VIPs[vip][l4].Rip[rip] = real
			}
		}
	}

	new._real = make(map[IP4]uint16)

	for k, v := range reals {
		if v.u {
			new._real[k] = v.n
		}
	}

	new.Reals = make(map[IP4]RI)

	for k, v := range reals {
		vlan, err := find_real_vlan(new, k)
		if err != nil {
			return err
		}
		new.Reals[k] = RI{Index: v.n, VLAN: vlan}
	}

	return nil
}

func _fix_idx(new, old *Config) error {
	type idx struct {
		n uint16
		u bool
	}

	new_index := func(m map[IP4]idx) (uint16, error) {
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

	for vip, services := range new.VIPs {
		for l4, service := range services {
			for rip, real := range service.Rip {

				var i uint16

				if v, ok := reals[rip]; ok {
					i = v.n
					v.u = true
					reals[rip] = v
				} else {
					var e error

					i, e = new_index(reals)

					if e != nil {
						return e
					}
					reals[rip] = idx{n: i, u: true}
				}

				real.Index = i
				real.Rip = rip
				new.VIPs[vip][l4].Rip[rip] = real
			}
		}
	}

	new._real = make(map[IP4]uint16)

	for k, v := range reals {
		if v.u {
			new._real[k] = v.n
		}
	}

	new.Reals = make(map[IP4]RI)

	for k, v := range reals {
		vlan, err := find_real_vlan(new, k)
		if err != nil {
			return err
		}
		new.Reals[k] = RI{Index: v.n, VLAN: vlan}
	}

	return nil
}

func real_info(c *Config) (map[IP4]Info, error) {

	real := make(map[IP4]Info)

	for _, vip := range c.VIPs {
		for _, service := range vip {
			for rip, _ := range service.Rip {

				var info Info

				if _, ok := real[rip]; ok {
					continue // this real ip already processed
				}

				if c.vlan_mode() {
					if vlan := c.find_vlan(rip); vlan == 0 {
						return nil, errors.New("Real " + rip.String() + " is not in a VLAN")
					} else {
						info = c._vlan[vlan] // use settings for this vlan
					}
				} else {
					info.VLAN = 0
					info.Source = c.Address   // send probes from primary ip address
					info.Iface = c._Interface // on the primary interface
				}

				real[rip] = info
			}
		}
	}

	return real, nil
}

func find_real_vlan(c *Config, rip IP4) (uint16, error) {
	if c.vlan_mode() {
		vlan := c.find_vlan(rip)
		if vlan == 0 {
			return 0, errors.New("Real " + rip.String() + " is not in a VLAN")
		}
		return vlan, nil
	}
	return 0, nil
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

		config.Address = src
		config._Interface = info.Iface

	} else {

		config.Address = src

		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			return nil, err
		}

		config._Interface = *iface

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		var found bool

		for _, addr := range addrs {

			ipaddr, _, err := net.ParseCIDR(addr.String())

			if err != nil {
				return nil, err
			}

			if ipaddr.String() == src.String() {
				found = true
			}
		}

		if !found {
			return nil, errors.New("Couldn't find IP " + src.String() + " on interface " + ifname)
		}
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
