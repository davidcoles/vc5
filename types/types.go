package types

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"
)

type NIC struct {
	Name  string
	IP    net.IP
	IPNet net.IPNet
	Iface net.Interface
}

type IP4 [4]byte
type IP6 [16]byte
type MAC [6]byte

type L4 struct {
	Port     uint16
	Protocol Protocol
}

type IP4s []IP4

func (h IP4s) Len() int           { return len(h) }
func (h IP4s) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h IP4s) Less(i, j int) bool { return cmpip4(h[i], h[j]) == -1 }

func cmpip4(a, b [4]byte) int {
	for n := 0; n < len(a); n++ {
		if a[n] < b[n] {
			return -1
		}
		if a[n] > b[n] {
			return 1
		}
	}
	return 0
}

func CmpIP4s(a, b IP4s) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if cmpip4(a[i], b[i]) != 0 {
			return false
		}
	}

	return true
}

type Protocol bool

const (
	TCP Protocol = false
	UDP          = true
)

func (p Protocol) string() string {

	if p {
		return "udp"
	}
	return "tcp"
}

func (p Protocol) String() string {
	return p.string()
}

func (p Protocol) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.string() + `"`), nil
}

func (p Protocol) MarshalText() ([]byte, error) {
	return []byte(`"` + p.string() + `"`), nil
}

type Thruple struct {
	IP       IP4
	Port     uint16
	Protocol Protocol
}

func (t *Thruple) L4() L4 {
	if t.Protocol == UDP {
		return L4{t.Port, true}
	}
	return L4{t.Port, false}
}

func (t *Thruple) String() string {
	return t.IP.String() + ":" + t.L4().String()
}

type RHI struct {
	Ip IP4
	Up bool
}

type Counters struct {
	Up         bool   `json:"up"`
	MAC        MAC    `json:"mac"`
	Concurrent int64  `json:"current_connections"`
	New_flows  uint64 `json:"total_connections"`
	Rx_packets uint64 `json:"rx_packets"`
	Rx_octets  uint64 `json:"rx_octets"`
	Qfailed    uint64 `json:"-"`
	Fp_count   uint64 `json:"-"`
	Fp_time    uint64 `json:"-"`
	Ip         IP4    `json:"-"`
	//Pps        uint64    `json:"-"`
	//Bps        uint64    `json:"-"`
	Latency   uint64    `json:"-"`
	DEFCON    uint8     `json:"-"`
	Rx_pps    uint64    `json:"rx_packets_per_second"`
	Rx_bps    uint64    `json:"rx_octets_per_second"`
	Timestamp time.Time `json:"-"`
	Vlan      uint16    `json:"-"`
}

func (c *Counters) PerSec(o Counters) {
	dur := uint64(c.Timestamp.Sub(o.Timestamp)) / uint64(time.Millisecond)

	if dur > 0 {
		c.Rx_pps = 1000 * ((c.Rx_packets - o.Rx_packets) / dur)
		c.Rx_bps = 1000 * ((c.Rx_octets - o.Rx_octets) / dur)
	}
}

type Scounters struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Up          bool                `json:"up"`
	Nalive      uint                `json:"live_backends"`
	Need        uint                `json:"need_backends"`
	Concurrent  int64               `json:"current_connections"`
	New_flows   uint64              `json:"total_connections"`
	Rx_packets  uint64              `json:"rx_packets"`
	Rx_octets   uint64              `json:"rx_octets"`
	Rx_pps      uint64              `json:"rx_packets_per_second"`
	Rx_bps      uint64              `json:"rx_octets_per_second"`
	Backends    map[string]Counters `json:"backends"`
	VIP         IP4                 `json:"vip"`
	Port        uint16              `json:"port"`
	Protocol    Protocol            `json:"protocol"`
	Delete      bool                `json:"-"`
}

func (c *Scounters) Service() Thruple {
	return Thruple{c.VIP, c.Port, c.Protocol}
}

func (c *Scounters) Sum() {
	for _, b := range c.Backends {
		c.New_flows += b.New_flows
		c.Rx_packets += b.Rx_packets
		c.Rx_octets += b.Rx_octets
		c.Rx_pps += b.Rx_pps
		c.Rx_bps += b.Rx_bps
		c.Concurrent += b.Concurrent
	}
}

func (i *IP4) UnmarshalJSON(d []byte) error {
	l := len(d)
	if l < 2 || d[0] != '"' || d[l-1] != '"' {
		return errors.New("Badly formated IPv4 address: " + string(d))
	}

	ip, ok := parseIP(string(d[1 : l-1]))

	if ok {
		i[0] = ip[0]
		i[1] = ip[1]
		i[2] = ip[2]
		i[3] = ip[3]
		return nil
	}
	return errors.New("Badly formated IPv4 address: " + string(d))
}

func (t Thruple) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.String() + `"`), nil
}

func (i IP4) MarshalText() ([]byte, error) {
	return []byte(i.string()), nil
}
func (i *IP4) UnmarshalText(t []byte) error {
	//return []byte(i.string()), nil
	ip, ok := parseIP(string(t))
	if !ok {
		return errors.New("Bad: " + string(t))
	}
	*i = ip
	return nil
}
func (l *L4) UnmarshalText(t []byte) error {
	pp := string(t)
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
	l.Port = uint16(port)
	l.Protocol = Protocol(udp)
	return nil
}

func (i IP4) MarshalJSON() ([]byte, error) {
	return []byte(`"` + i.String() + `"`), nil
}

func (m MAC) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.String() + `"`), nil
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

func (i IP4) string() string {
	return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3])
}
func (i IP4) String() string {
	return i.string()
}

func (l L4) string() string {
	if l.Protocol {
		return fmt.Sprint(l.Port, "/udp")
	}
	return fmt.Sprint(l.Port, "/tcp")
}

func (l L4) MarshalText() ([]byte, error) {
	return []byte(l.string()), nil
}

func (l L4) String() string {
	if l.Protocol {
		return fmt.Sprint(l.Port, "/udp")
	}
	return fmt.Sprint(l.Port, "/tcp")
}

func (l L4) MarshalJSON() ([]byte, error) {
	return []byte(`"` + l.String() + `"`), nil
}

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

type B12s [][12]byte
type B12 [12]byte

func (h B12s) Len() int           { return len(h) }
func (h B12s) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h B12s) Less(i, j int) bool { return CmpB12(h[i], h[j]) == -1 }

func Cmpmac(a, b [6]byte) int {
	for n := 0; n < len(a); n++ {
		if a[n] < b[n] {
			return -1
		}
		if a[n] > b[n] {
			return 1
		}
	}
	return 0
}

func CmpB12s(a, b [][12]byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if CmpB12(a[i], b[i]) != 0 {
			return false
		}
	}

	return true
}

func CmpB12(a, b [12]byte) int {
	for n := 0; n < len(a); n++ {
		if a[n] < b[n] {
			return -1
		}
		if a[n] > b[n] {
			return 1
		}
	}
	return 0
}
