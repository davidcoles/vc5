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

package kernel

import (
	"bufio"
	_ "embed"
	"errors"
	"net"
	"os"
	"regexp"
	"sort"
	"unsafe"

	"github.com/davidcoles/vc5/kernel/maglev"
	"github.com/davidcoles/vc5/kernel/xdp"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/monitor/healthchecks"
	"github.com/davidcoles/vc5/types"
)

//go:embed bpf/bpf.o
var BPF_O []byte

type uP = unsafe.Pointer
type IP4 = types.IP4
type IP4s = types.IP4s
type MAC = types.MAC
type L4 = types.L4
type Protocol = types.Protocol

type Healthchecks = healthchecks.Healthchecks
type Report = monitor.Report
type Real = healthchecks.Real
type Backend = healthchecks.Backend
type Service = healthchecks.Service

type maps = Maps
type Maps struct {
	m      map[string]int
	defcon uint8
	multi  bool
}

type bpf_real struct {
	rip  [4]byte //__be32
	vid  [2]byte //__be16
	mac  [6]byte
	flag [4]byte
}

type bpf_vrpp struct {
	vip      [4]byte //__be32 vip;
	rip      [4]byte //__be32 rip;
	port     [2]byte //__be16 port;
	protocol byte    //__u8 protocol;
	pad      byte    //__u8 pad;
}

type bpf_counter struct {
	packets uint64
	octets  uint64
	flows   uint64
	_pad    uint64
}

type bpf_setting struct {
	heartbeat uint64
	defcon    uint8 // 3 bit
	era       uint8 // 1 bit
	multi     uint8 // 1 bit
	// [0:0][0:0][0][0:0:0]
}

var SETTINGS bpf_setting = bpf_setting{defcon: 5}

type bpf_global struct {
	rx_packets     uint64
	rx_octets      uint64
	perf_packets   uint64
	perf_timens    uint64
	perf_timer     uint64
	settings_timer uint64
	new_flows      uint64
	dropped        uint64
}

type bpf_service struct {
	vip      [4]byte
	port     [2]byte
	protocol uint8
	_pad     uint8
}

type bpf_backend struct {
	real [256]bpf_real
	hash [8192]byte
}

type bpf_active struct {
	_total  uint64
	current int64
}

type real_info struct {
	idx uint16
	mac MAC
}

type Target struct {
	VIP      IP4
	RIP      IP4
	Port     uint16
	Protocol uint8
}

func (c *bpf_counter) add(a bpf_counter) {
	c.octets += a.octets
	c.packets += a.packets
	c.flows += a.flows
}

func (g *bpf_global) add(a bpf_global) {
	g.rx_packets += a.rx_packets
	g.rx_octets += a.rx_octets
	g.perf_packets += a.perf_packets
	g.perf_timens += a.perf_timens
	//g.defcon = a.defcon
	g.new_flows += a.new_flows
}

func Open(native bool, vetha, vethb string, eth ...string) (*Maps, error) {
	var m maps
	m.m = make(map[string]int)
	m.defcon = 5

	//x, err := xdp.LoadBpfFile_(BPF_O, "incoming", "outgoing", native, vetha, vethb, eth...)

	x, err := xdp.LoadBpfProgram(BPF_O)

	if err != nil {
		return nil, err
	}

	err = x.LoadBpfSection("outgoing", false, vetha)
	if err != nil {
		return nil, err
	}

	err = x.LoadBpfSection("outgoing", true, vethb)
	if err != nil {
		return nil, err
	}

	for _, e := range eth {
		err = x.LoadBpfSection("incoming", native, e)
		if err != nil {
			return nil, err
		}
	}

	// balancer
	if m.m["service_backend"], err = find_map(x, "service_backend", 8, (256*16)+8192); err != nil {
		return nil, err
	}

	// nat
	if m.m["nat"], err = find_map(x, "nat", 20, 28); err != nil {
		return nil, err
	}

	// stats
	if m.m["globals"], err = find_map(x, "globals", 4, 64); err != nil {
		return nil, err
	}

	if m.m["vrpp_counter"], err = find_map(x, "vrpp_counter", 12, 32); err != nil {
		return nil, err
	}

	if m.m["vrpp_concurrent"], err = find_map(x, "vrpp_concurrent", 12, 16); err != nil {
		return nil, err
	}

	// control
	if m.m["settings"], err = find_map(x, "settings", 4, 16); err != nil {
		return nil, err
	}

	//if m.m["redirect_map_hash"], err = find_map(x, "redirect_map_hash", 4, 4); err != nil {
	//	return nil, err
	//}

	if m.m["redirect_map"], err = find_map(x, "redirect_map", 4, 4); err != nil {
		return nil, err
	}

	if m.m["redirect_mac"], err = find_map(x, "redirect_mac", 4, 6); err != nil {
		return nil, err
	}

	if m.m["prefix_counters"], err = find_map(x, "prefix_counters", 4, 8); err != nil {
		return nil, err
	}

	var zero uint32
	s := bpf_setting{defcon: m.defcon, era: 0}

	if xdp.BpfMapUpdateElem(m.settings(), uP(&zero), uP(&s), xdp.BPF_ANY) != 0 {
		return nil, errors.New("Failed to load settings")
	}

	return &m, nil
}

func (m *maps) service_backend() int { return m.m["service_backend"] }
func (m *maps) vrpp_counter() int    { return m.m["vrpp_counter"] }
func (m *maps) vrpp_concurrent() int { return m.m["vrpp_concurrent"] }
func (m *maps) globals() int         { return m.m["globals"] }
func (m *maps) settings() int        { return m.m["settings"] }
func (m *maps) nat() int             { return m.m["nat"] }
func (m *maps) prefix_counters() int { return m.m["prefix_counters"] }

//func (m *maps) redirect_map_hash() int { return m.m["redirect_map_hash"] }
func (m *maps) redirect_map() int { return m.m["redirect_map"] }
func (m *maps) redirect_mac() int { return m.m["redirect_mac"] }

const PREFIXES = 1048576

func (m *maps) ReadPrefixCounters() [PREFIXES]uint64 {

	var prefixes [PREFIXES]uint64

	for i, _ := range prefixes {

		j := uint32(i)
		c := make([]uint64, xdp.BpfNumPossibleCpus())

		xdp.BpfMapLookupElem(m.prefix_counters(), uP(&j), uP(&(c[0])))

		var x uint64

		for _, v := range c {
			x += v
		}

		prefixes[i] = x
	}

	return prefixes
}

func (m *maps) update_service_backend(key *bpf_service, b *bpf_backend, flag uint64) int {

	all := make([]bpf_backend, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *b
	}

	return xdp.BpfMapUpdateElem(m.service_backend(), uP(key), uP(&(all[0])), flag)
}

func (m *maps) update_vrpp_counter(v *bpf_vrpp, c *bpf_counter, flag uint64) int {

	all := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		all[n] = *c
	}

	return xdp.BpfMapUpdateElem(m.vrpp_counter(), uP(v), uP(&(all[0])), flag)
}

func (m *maps) lookup_vrpp_counter(v *bpf_vrpp, c *bpf_counter) int {

	co := make([]bpf_counter, xdp.BpfNumPossibleCpus())

	ret := xdp.BpfMapLookupElem(m.vrpp_counter(), uP(v), uP(&(co[0])))

	var x bpf_counter

	for _, v := range co {
		x.add(v)
	}

	*c = x

	return ret
}

func (m *maps) update_vrpp_concurrent(era bool, v *bpf_vrpp, a *bpf_active, flag uint64) int {

	all := make([]bpf_active, xdp.BpfNumPossibleCpus())

	for n, _ := range all {
		if a != nil {
			all[n] = *a
		}
	}

	if era {
		v.pad = 1
	} else {
		v.pad = 0
	}

	return xdp.BpfMapUpdateElem(m.vrpp_concurrent(), uP(v), uP(&(all[0])), flag)
}

func (m *maps) lookup_vrpp_concurrent(era bool, v *bpf_vrpp, a *bpf_active) int {

	co := make([]bpf_active, xdp.BpfNumPossibleCpus())

	if era {
		v.pad = 1
	} else {
		v.pad = 0
	}

	ret := xdp.BpfMapLookupElem(m.vrpp_concurrent(), uP(v), uP(&(co[0])))

	var x bpf_active

	for _, v := range co {
		if v.current > 0 {
			x.current += v.current
		}
	}

	*a = x

	return ret
}

func (m *maps) write_settings() {
	var zero uint32
	SETTINGS.heartbeat = 0
	SETTINGS.defcon = m.defcon

	if m.multi {
		SETTINGS.multi = 1
	} else {
		SETTINGS.multi = 0
	}

	xdp.BpfMapUpdateElem(m.settings(), uP(&zero), uP(&SETTINGS), xdp.BPF_ANY)
}

func (m *maps) MODE(mode bool) {
	if mode {
		m.multi = true
		SETTINGS.multi = 1
	} else {
		m.multi = false
		SETTINGS.multi = 0
	}

	m.write_settings()
}

func (m *maps) ERA(era uint8) {
	SETTINGS.era = era
	m.write_settings()
}

func (m *maps) DEFCON(d uint8) uint8 {
	if d <= 5 {
		m.defcon = d
		SETTINGS.defcon = m.defcon
	}
	m.write_settings()
	return m.defcon
}

func (m *maps) lookup_globals(g *bpf_global) int {

	all := make([]bpf_global, xdp.BpfNumPossibleCpus())
	var zero uint32

	ret := xdp.BpfMapLookupElem(m.globals(), uP(&zero), uP(&(all[0])))

	var x bpf_global

	for _, v := range all {
		x.add(v)
	}

	*g = x

	return ret
}

func natAddress(n uint16, ip IP4) IP4 {
	hl := htons(n)
	var nat IP4
	if n != 0 {
		nat[0] = ip[0]
		nat[1] = ip[1]
		nat[2] = hl[0]
		nat[3] = hl[1]
	}
	return nat
}

func find_map(x *xdp.XDP, name string, ks int, rs int) (int, error) {
	m := x.FindMap(name)

	if m == -1 {
		return 0, errors.New(name + " not found")
	}

	if !x.CheckMap(m, ks, rs) {
		return 0, errors.New(name + " incorrect size")
	}

	return m, nil
}

func htons(p uint16) [2]byte {
	var hl [2]byte
	hl[0] = byte(p >> 8)
	hl[1] = byte(p & 0xff)
	return hl
}

func arp() map[IP4]MAC {

	ip2mac := make(map[IP4]MAC)
	ip2nic := make(map[IP4]*net.Interface)

	re := regexp.MustCompile(`^(\S+)\s+0x1\s+0x[26]\s+(\S+)\s+\S+\s+(\S+)$`)

	file, err := os.OpenFile("/proc/net/arp", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) > 3 {

			ip := net.ParseIP(m[1])

			if ip == nil {
				continue
			}

			ip = ip.To4()

			if ip == nil || len(ip) != 4 {
				continue
			}

			hw, err := net.ParseMAC(m[2])

			if err != nil || len(hw) != 6 {
				continue
			}

			iface, err := net.InterfaceByName(m[3])

			if err != nil {
				continue
			}

			var ip4 IP4
			var mac [6]byte

			copy(ip4[:], ip[:])
			copy(mac[:], hw[:])

			if ip4.String() == "0.0.0.0" {
				continue
			}

			if mac == [6]byte{0, 0, 0, 0, 0, 0} {
				continue
			}

			ip2mac[ip4] = mac
			ip2nic[ip4] = iface
		}
	}

	return ip2mac
}

func maglev8192(m map[[4]byte]uint8) (r [8192]uint8, b bool) {

	if len(m) < 1 {
		return r, false
	}

	a := IP4s(make([]IP4, len(m)))

	n := 0
	for k, _ := range m {
		a[n] = k
		n++
	}

	sort.Sort(a)

	h := make([][]byte, len(a))

	for k, v := range a {
		b := make([]byte, 4)
		copy(b[:], v[:])
		h[k] = b
	}

	t := maglev.Maglev8192(h)

	for k, v := range t {
		ip := a[v]
		x, ok := m[ip]
		if !ok {
			return r, false
		}
		r[k] = x
	}

	return r, true
}
