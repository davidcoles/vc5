package types

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"
)

func htons(p uint16) [2]byte {
	var hl [2]byte
	hl[0] = byte(p >> 8)
	hl[1] = byte(p & 0xff)
	return hl
}

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

func (l *L4) NP() [2]byte { return htons(l.Port) }
func (l *L4) PN() byte    { return l.Protocol.Number() }

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

const IPPROTO_TCP = 0x06
const IPPROTO_UDP = 0x11

func (p Protocol) Number() uint8 {
	if p {
		return IPPROTO_UDP
	}
	return IPPROTO_TCP
}
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
	Up         bool      `json:"up"`
	MAC        MAC       `json:"mac"`
	Concurrent int64     `json:"current_connections"`
	New_flows  uint64    `json:"total_connections"`
	Rx_packets uint64    `json:"rx_packets"`
	Rx_octets  uint64    `json:"rx_octets"`
	Qfailed    uint64    `json:"-"`
	Fp_count   uint64    `json:"-"`
	Fp_time    uint64    `json:"-"`
	Ip         IP4       `json:"-"`
	Latency    uint64    `json:"-"`
	DEFCON     uint8     `json:"-"`
	Rx_pps     uint64    `json:"rx_packets_per_second"`
	Rx_bps     uint64    `json:"rx_octets_per_second"`
	Timestamp  time.Time `json:"-"`
	Vlan       uint16    `json:"-"`
}

func (c *Counters) PerSec(o Counters) {
	duration_ms := uint64(c.Timestamp.Sub(o.Timestamp)) / uint64(time.Millisecond)

	if duration_ms > 0 {
		c.Rx_pps = (1000 * (c.Rx_packets - o.Rx_packets)) / duration_ms
		c.Rx_bps = (1000 * (c.Rx_octets - o.Rx_octets)) / duration_ms
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

func (i IP4) IsNil() bool {
	var n IP4
	if i == n {
		return true
	}
	return false
}

func (m MAC) IsNil() bool {
	var n MAC
	if m == n {
		return true
	}
	return false
}

func (i *IP4) IP() net.IP {
	return net.IPv4(i[0], i[1], i[2], i[3])
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

func (m *MAC) UnmarshalJSON(d []byte) error {
	l := len(d)
	if l < 2 || d[0] != '"' || d[l-1] != '"' {
		return errors.New("Badly formated MAC address: " + string(d))
	}

	mac, ok := parseMAC(string(d[1 : l-1]))

	if ok {
		m[0] = mac[0]
		m[1] = mac[1]
		m[2] = mac[2]
		m[3] = mac[3]
		m[4] = mac[4]
		m[5] = mac[5]
		return nil
	}
	return errors.New("Badly formated MAC address: " + string(d))
}

func (t Thruple) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.String() + `"`), nil
}

func (i IP4) MarshalText() ([]byte, error) {
	return []byte(i.string()), nil
}

func (i *IP4) UnmarshalText(t []byte) error {
	ip, ok := parseIP(string(t))
	if !ok {
		return errors.New("Bad: " + string(t))
	}
	*i = ip
	return nil
}

func (l *L4) UnmarshalText(t []byte) error {
	pp := string(t)
	var pt, pr string
	{
		re := regexp.MustCompile(`^(udp|tcp):([1-9][0-9]*)$`)
		ma := re.FindStringSubmatch(pp)
		if len(ma) == 3 {
			pr = ma[1]
			pt = ma[2]
		} else {
			re := regexp.MustCompile(`^([1-9][0-9]*)/(udp|tcp)$`)
			ma := re.FindStringSubmatch(pp)
			if len(ma) == 3 {
				pt = ma[1]
				pr = ma[2]
			} else {
				return errors.New("Service is not of the form (tcp|udp):<port> or <port>/(udp|tcp): " + pp)
			}
		}
	}

	port, err := strconv.Atoi(pt)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("Invalid port number : " + pp)
	}

	var udp bool
	if pr == "udp" {
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

func ParseIP(ip string) ([4]byte, bool) {
	return parseIP(ip)
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

func parseMAC(s string) ([6]byte, bool) {
	var addr [6]byte
	re := regexp.MustCompile(`^([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2})$`)
	m := re.FindStringSubmatch(s)

	if len(m) != 7 {
		return addr, false
	}

	for n, _ := range addr {

		b, err := hex.DecodeString(m[n+1])

		if err != nil || len(b) != 1 {
			return addr, false
		}
		addr[n] = b[0]
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
	return fmt.Sprintf("%s:%d", l.Protocol, l.Port)
	if l.Protocol {
		return fmt.Sprint(l.Port, "/udp")
	}
	return fmt.Sprint(l.Port, "/tcp")
}

func (l L4) MarshalText() ([]byte, error) {
	return []byte(l.string()), nil
}

func (l L4) String() string {
	return l.string()
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

type NET struct {
	IP   IP4
	Mask IP4
}

func (i *NET) mask() (ip IP4) {
	ip[0] = i.IP[0] & i.Mask[0]
	ip[1] = i.IP[1] & i.Mask[1]
	ip[2] = i.IP[2] & i.Mask[2]
	ip[3] = i.IP[3] & i.Mask[3]
	return
}

func (i *NET) Net() (ip IP4) {
	ip[0] = i.IP[0] & i.Mask[0]
	ip[1] = i.IP[1] & i.Mask[1]
	ip[2] = i.IP[2] & i.Mask[2]
	ip[3] = i.IP[3] & i.Mask[3]
	return
}

func (i *NET) NetMask() NET {
	return NET{IP: i.Net(), Mask: i.Mask}
}

func (i *NET) IPNet() (ip net.IP, ipnet net.IPNet) {
	ip = net.IPv4(i.IP[0], i.IP[1], i.IP[2], i.IP[3])
	n := i.mask()
	ipnet.IP = net.IPv4(n[0], n[1], n[2], n[3])
	ipnet.Mask = net.IPv4Mask(i.Mask[0], i.Mask[1], i.Mask[2], i.Mask[3])
	return

}

func (n NET) MarshalJSON() ([]byte, error) {
	return []byte(`"` + n.IP.String() + "/" + n.Mask.String() + `"`), nil
}

func (c *NET) UnmarshalJSON(data []byte) error {

	re := regexp.MustCompile(`^"([^"]+)"$`)

	m := re.FindStringSubmatch(string(data))

	if len(m) != 2 {
		return errors.New("Badly formed CIDR")
	}

	re2 := regexp.MustCompile(`^([^/]+)/([^/][^/][^/]+)$`)

	m2 := re2.FindStringSubmatch(m[1])

	if len(m2) == 3 {
		ip, ok := parseIP(m2[1])

		if !ok {
			return errors.New("Badly formed NET IP")
		}

		mask, ok := parseIP(m2[2])
		if !ok {
			return errors.New("Badly formed NET mask")
		}

		c.IP = ip
		c.Mask = mask
		return nil
	}

	ip, ipn, err := net.ParseCIDR(m[1])

	if err != nil {
		return err
	}

	ip4 := ip.To4()

	if len(ip4) != 4 || (ip4[0] == 0 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 0) {
		return errors.New("Invalid IP")
	}

	mask := ipn.Mask

	if len(mask) != 4 || (mask[0] == 0 && mask[1] == 0 && mask[2] == 0 && mask[3] == 0) {
		return errors.New("Invalid mask")
	}

	copy(c.IP[:], ip4[:])
	copy(c.Mask[:], mask[:])

	return nil
}

func (n *NET) Parse(s string) error {
	m, err := Net(s)
	if err != nil {
		return err
	}
	*n = m
	return nil
}

func Net(s string) (NET, error) {

	var n NET

	ip, ipn, err := net.ParseCIDR(s)

	if err != nil {
		return n, err
	}

	ip4 := ip.To4()

	if len(ip4) != 4 || (ip4[0] == 0 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 0) {
		return n, errors.New("Invalid IP")
	}

	mask := ipn.Mask

	if len(mask) != 4 || (mask[0] == 0 && mask[1] == 0 && mask[2] == 0 && mask[3] == 0) {
		return n, errors.New("Invalid mask")
	}

	copy(n.IP[:], ip4[:])
	copy(n.Mask[:], mask[:])

	return n, nil
}

type Logger interface {
	EMERG(string, ...interface{})
	ALERT(string, ...interface{})
	CRIT(string, ...interface{})
	ERR(string, ...interface{})
	WARNING(string, ...interface{})
	NOTICE(string, ...interface{})
	INFO(string, ...interface{})
	DEBUG(string, ...interface{})
}

type NilLogger struct {
}

func (l *NilLogger) EMERG(f string, e ...interface{})   {}
func (l *NilLogger) ALERT(f string, e ...interface{})   {}
func (l *NilLogger) CRIT(f string, e ...interface{})    {}
func (l *NilLogger) ERR(f string, e ...interface{})     {}
func (l *NilLogger) WARNING(f string, e ...interface{}) {}
func (l *NilLogger) NOTICE(f string, e ...interface{})  {}
func (l *NilLogger) INFO(f string, e ...interface{})    {}
func (l *NilLogger) DEBUG(f string, e ...interface{})   {}

type IPPort struct {
	IP   IP4
	Port uint16
}

func (i *IPPort) MarshalJSON() ([]byte, error) {
	//return []byte(`"` + fmt.Sprintf("%s:%d", i.IP, i.Port) + `"`), nil
	return []byte(fmt.Sprintf(`"%s:%d"`, i.IP, i.Port)), nil
}

func (i *IPPort) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("Badly formed ip:port")
	}

	return i.UnmarshalText(data[1 : l-1])
}

func (i IPPort) MarshalText() ([]byte, error) {
	if i.Port != 0 {
		return []byte(fmt.Sprintf("%s:%d", i.IP, i.Port)), nil
	}

	return []byte(i.IP.String()), nil
}

func (i *IPPort) String() string {
	if i.Port != 0 {
		return fmt.Sprintf("%s:%d", i.IP, i.Port)
	}

	return i.IP.String()
}

func (i *IPPort) UnmarshalText(data []byte) error {

	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)(|:(\d+))$`)

	m := re.FindStringSubmatch(string(data))

	if len(m) != 4 {
		return errors.New("Badly formed ip:port")
	}

	ip, ok := parseIP(string(m[1]))

	if !ok {
		return errors.New("Badly formed ip:port")
	}

	i.IP = ip

	if m[3] != "" {

		port, err := strconv.Atoi(m[3])
		if err != nil {
			return err
		}

		if port < 0 || port > 65535 {
			return errors.New("Badly formed ip:port")
		}

		i.Port = uint16(port)
	}

	return nil
}
