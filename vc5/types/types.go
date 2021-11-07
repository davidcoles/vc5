package types

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

type IP4 [4]byte
type IP6 [16]byte
type MAC [6]byte

type RHI struct {
	Ip IP4
	Up bool
}

type Counters struct {
	Up         bool   `json:"up"`
	MAC        string `json:"mac"`
	Concurrent int64  `json:"current_connections"`
	New_flows  uint64 `json:"total_connections"`
	Rx_packets uint64 `json:"rx_packets"`
	Rx_bytes   uint64 `json:"rx_octets"`
	Qfailed    uint64
	Fp_count   uint64
	Fp_time    uint64
	Ip         IP4
}
type Scounters struct {
	Sname       string
	Name        string `json:"name"`
	Description string `json:"description"`
	Up          bool   `json:"up"`
	Nalive      uint   `json:"live_backends"`
	Need        uint   `json:"need_backends"`
	Concurrent  int64  `json:"current_connections"`
	New_flows   uint64 `json:"total_connections"`
	Rx_packets  uint64 `json:"rx_packets"`
	Rx_bytes    uint64 `json:"rx_octets"`
	fp_count    uint64
	fp_time     uint64

	//name     string
	Backends map[string]Counters `json:"backends"`
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

//func (i *IP4) MarshalJSON() ([]byte, error) {
//	return []byte(i.String()), nil
//}
func (i IP4) MarshalJSON() ([]byte, error) {
	return []byte(`"` + i.String() + `"`), nil
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

func (i IP4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3])
}

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}
