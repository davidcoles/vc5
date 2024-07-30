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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/bgp"
	"github.com/davidcoles/cue/mon"

	"vc5"
)

const (
	TCP = 0x06
	UDP = 0x11
)

type Real struct {
	Checks   []mon.Check `json:"checks,omitempty"`
	Disabled bool        `json:"disabled,omitempty"`
	Weight   uint8       `json:"weight,omitempty"`
}

// Describes a Layer 4 service
type Service struct {
	// The service name - should be a short identifier, suitable for using as a Prometheus label value
	Name string `json:"name,omitempty"`

	// A short description of the service
	Description string `json:"description,omitempty"`

	// critical, high, medium or low (default is critical)
	Priority priority `json:"priority"`

	// The minimum number of real servers which need to be healthy to consider this service viable
	Need uint8 `json:"need,omitempty"`

	// Backend servers and corresponding health checks
	Destinations map[ipport]Real `json:"reals,omitempty"`

	// If set to true, the backend selection algorithm will not include layer 4 port numbers
	Sticky bool `json:"sticky,omitempty"`

	Scheduler string `json:"scheduler"`
	Persist   uint32 `json:"persist"`         // used in IPVS version
	Reset     bool   `json:"reset,omitempty"` // used in IPVS version
}

type services map[Tuple]Service

// Load balancer configuration
type Config struct {
	Services services `json:"services,omitempty"`

	// VLAN ID to subnet mappings
	VLANs map[uint16]Prefix `json:"vlans,omitempty"`

	BGP map[string]bgp.Parameters `json:"bgp,omitempty"`

	Learn      time.Duration `json:"learn,omitempty"`
	Listen     bool          `json:"listen,omitempty"`
	Multicast  string        `json:"multicast,omitempty"`
	Webserver  string        `json:"webserver,omitempty"`
	Webroot    string        `json:"webroot,omitempty"`
	Logging    vc5.Logging_  `json:"logging,omitempty"`
	Native     bool          `json:"native,omitempty"`
	Untagged   bool          `json:"untagged,omitempty"`
	Address    string        `json:"address,omitempty"`
	Interfaces []string      `json:"interfaces,omitempty"`
}

func (c *Config) logging() vc5.Logging {
	return c.Logging.Logging()
}

func (c *Config) bgp(asn uint16, mp bool) map[string]bgp.Parameters {
	if asn > 0 {
		return map[string]bgp.Parameters{"127.0.0.1": bgp.Parameters{ASNumber: asn, HoldTime: 4, Multiprotocol: mp}}
	}

	return c.BGP
}

func (c *Config) vlans() map[uint16]net.IPNet {
	ret := map[uint16]net.IPNet{}

	for k, v := range c.VLANs {
		ret[k] = net.IPNet(v)
	}

	return ret
}

func (c *Config) priorities() map[netip.Addr]priority {

	priorities := map[netip.Addr]priority{}

	for k, v := range c.Services {
		p, ok := priorities[k.Address]

		if !ok {
			p = LOW
			priorities[k.Address] = p
		}

		if v.Priority < p {
			priorities[k.Address] = v.Priority
		}
	}

	return priorities
}

// Reads the load-balancer configuration from a JSON file. Returns a
// pointer to the Config object on success, and sets the error to
// non-nil on failure.
func Load(file string) (*Config, error) {

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

	if len(config.VLANs) != 0 {
		for _, s := range config.Services {
			for d, _ := range s.Destinations {

				var ok bool

				for _, p := range config.VLANs {
					if p.Contains(d.Address) {
						ok = true
					}
				}

				if !ok {
					return nil, fmt.Errorf("Destination server %s is not in a declared VLAN", d.Address)
				}

			}
		}
	}

	return &config, nil
}

type ipport = IPPort

type IPPort struct {
	Address netip.Addr
	Port    uint16
}

func (i *ipport) MarshalJSON() ([]byte, error) {
	text, err := i.MarshalText()

	if err != nil {
		return nil, err
	}

	return []byte(`"` + string(text) + `"`), nil
}

func (i *ipport) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("Badly formed ip:port")
	}

	return i.UnmarshalText(data[1 : l-1])
}

func (i ipport) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%s:%d", i.Address, i.Port)), nil
}

func (i *ipport) UnmarshalText(data []byte) error {

	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)(|:(\d+))$`)

	m := re.FindStringSubmatch(string(data))

	if len(m) != 4 {
		return errors.New("Badly formed ip:port")
	}

	ip, err := netip.ParseAddr(m[1])

	if err != nil {
		return err
	}

	if !ip.Is4() {
		return errors.New("Badly formed ip:port - IP: " + m[1])
	}

	i.Address = ip

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

/**********************************************************************/

type tuple = Tuple
type Tuple struct {
	Address  netip.Addr
	Port     uint16
	Protocol uint8
}

func (t *Tuple) string() string {
	var p string

	switch t.Protocol {
	case TCP:
		p = "tcp"
	case UDP:
		p = "udp"
	default:
		p = fmt.Sprint(t.Protocol)
	}

	return fmt.Sprintf("%s:%d:%s", t.Address, t.Port, p)
}

func (i *Tuple) Compare(j *Tuple) (r int) {
	if r = i.Address.Compare(j.Address); r != 0 {
		return r
	}

	if i.Port < j.Port {
		return -1
	}

	if i.Port > j.Port {
		return 1
	}

	if i.Protocol < j.Protocol {
		return -1
	}

	if i.Protocol > j.Protocol {
		return 1
	}

	return 0
}

func (t *Tuple) MarshalJSON() ([]byte, error) {
	text, err := t.MarshalText()

	if err != nil {
		return nil, err
	}

	return []byte(`"` + string(text) + `"`), nil
}

func (t *Tuple) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("Badly formed ip:port")
	}

	return t.UnmarshalText(data[1 : l-1])
}

func (t Tuple) MarshalText() ([]byte, error) {

	var p string

	switch t.Protocol {
	case TCP:
		p = "tcp"
	case UDP:
		p = "udp"
	default:
		return nil, errors.New("Invalid protocol")
	}

	return []byte(fmt.Sprintf("%s:%d:%s", t.Address, t.Port, p)), nil
}

func (t *Tuple) UnmarshalText(data []byte) error {

	text := string(data)

	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+):(\d+):(tcp|udp)$`)

	m := re.FindStringSubmatch(text)

	if len(m) != 4 {
		return errors.New("Badly formed ip:port:protocol - " + text)
	}

	ip, err := netip.ParseAddr(m[1])

	if err != nil {
		return err
	}

	if !ip.Is4() {
		return errors.New("Badly formed ip:port:protocol - IP " + text)
	}

	t.Address = ip

	port, err := strconv.Atoi(m[2])
	if err != nil {
		return err
	}

	if port < 0 || port > 65535 {
		return errors.New("Badly formed ip:port:protocol, port out of rance 0-65535 - " + text)
	}

	t.Port = uint16(port)

	switch m[3] {
	case "tcp":
		t.Protocol = TCP
	case "udp":
		t.Protocol = UDP
	default:
		return errors.New("Badly formed ip:port:protocol, tcp/udp - " + text)
	}

	return nil
}

type Prefix net.IPNet

func (p *Prefix) String() string {
	return (*net.IPNet)(p).String()
}

func (p *Prefix) Contains(i netip.Addr) bool {
	var ip net.IP
	if i.Is4() {
		t := i.As4()
		ip = t[:]
	} else if i.Is6() {
		t := i.As16()
		ip = t[:]
	}

	return (*net.IPNet)(p).Contains(ip)
}

func (p *Prefix) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("CIDR address should be a string: " + string(data))
	}

	cidr := string(data[1 : l-1])

	ip, ipnet, err := net.ParseCIDR(cidr)

	if err != nil {
		return err
	}

	if ip.String() != ipnet.IP.String() {
		return errors.New("CIDR address contains host portion: " + cidr)
	}

	*p = Prefix(*ipnet)

	return nil
}

func (c *Config) parse() []cue.Service {

	var services []cue.Service

	for ipp, svc := range c.Services {

		service := cue.Service{
			Address:   ipp.Address,
			Port:      ipp.Port,
			Protocol:  ipp.Protocol,
			Required:  svc.Need,
			Scheduler: svc.Scheduler,
			Persist:   svc.Persist,
			Sticky:    svc.Sticky,
			Reset:     svc.Reset,
		}

		for ap, dst := range svc.Destinations {

			destination := cue.Destination{
				Address:  ap.Address,
				Port:     ap.Port,
				Weight:   dst.Weight,
				Disabled: dst.Disabled,
				Checks:   append([]mon.Check{}, dst.Checks...),
			}

			service.Destinations = append(service.Destinations, destination)

		}

		services = append(services, service)
	}

	return services
}

type protocol uint8

func (p protocol) MarshalText() ([]byte, error) {
	switch p {
	case TCP:
		return []byte("tcp"), nil
	case UDP:
		return []byte("udp"), nil
	}
	return nil, errors.New("Invalid protocol")
}

func (p protocol) string() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return fmt.Sprintf("%d", p)
}

type priority uint8

const CRITICAL = 0
const HIGH = 1
const MEDIUM = 2
const LOW = 3

func (p *priority) UnmarshalText(data []byte) error {

	text := string(data)

	switch text {
	case "critical":
		*p = CRITICAL
	case "high":
		*p = HIGH
	case "medium":
		*p = MEDIUM
	case "low":
		*p = LOW
	default:
		return errors.New("Invalid prority")
	}
	return nil
}

func (p priority) MarshalText() ([]byte, error) {
	switch p {
	case CRITICAL:
		return []byte("critcal"), nil
	case HIGH:
		return []byte("high"), nil
	case MEDIUM:
		return []byte("medium"), nil
	case LOW:
		return []byte("low"), nil
	}
	return nil, errors.New("Invalid prority")
}
