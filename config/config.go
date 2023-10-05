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

// This package provides structures representing a load-balancer
// configuration which would typically be unmarshalled from a JSON
// file at runtime. It is expected that a separate, human-editable,
// format would be processed to create the JSON representation.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"

	"github.com/davidcoles/vc5/types"
)

// Describes a Layer 4 or Layer 7 health check
type Check struct {
	//Type string `json:"type,omitempty"`
	Type string `json:"type,omitempty"`

	// TCP/UDP port to use for L4/L7 checks
	Port uint16 `json:"port,omitempty"`

	// HTTP Host header to send in healthcheck
	Host string `json:"host,omitempty"`

	// Path of resource to use when building a URI for HTTP/HTTPS healthchecks
	Path string `json:"path,omitempty"`

	// Expected HTTP status code to allow check to succeed
	Expect uint16 `json:"expect,omitempty"`

	// HTTP Method
	Method method `json:"method,omitempty"`
}

func (c *Check) Unzero(p uint16) {
	if c.Port == 0 {
		c.Port = p
	}
}

type Real struct {
	//Checks   Checks `json:"checks,omitempty"`
	Checks   []Check `json:"checks,omitempty"`
	Disabled bool    `json:"disabled,omitempty"`
	Weight   uint16  `json:"weight,omitempty"`
}

// Inventory of healthchecks required to pass to consider backend as healthy
type Checks struct {
	HTTP  []Check `json:"http,omitempty"`  // L7 HTTP checks
	HTTPS []Check `json:"https,omitempty"` // L7 HTTPS checks - certificate is not validated
	//TCP    []Check `json:"tcp,omitempty"`    // L4 SYN, SYN/ACK, ACK checks
	SYN    []Check `json:"syn,omitempty"`    // L4 SYN, SYN-ACK half-open checks
	DNS    []Check `json:"dns,omitempty"`    // L7 UDP DNS queries: CHAOS TXT version.bind - only response transaction ID is checked
	DNSTCP []Check `json:"dnstcp,omitempty"` // L7 TCP DNS queries: CHAOS TXT version.bind - only response transaction ID is checked
}

func (c *Checks) Slice() []Check {
	return nil
}

func (c *Checks) DefaultPort(p uint16) {

	u := func(c Check, p uint16) Check {
		c.Unzero(p)
		return c
	}

	for i, v := range c.HTTP {
		c.HTTP[i] = u(v, p)
	}

	for i, v := range c.HTTPS {
		c.HTTPS[i] = u(v, p)
	}

	//for i, v := range c.TCP {
	//	c.TCP[i] = u(v, p)
	//}

	for i, v := range c.SYN {
		c.SYN[i] = u(v, p)
	}

	for i, v := range c.DNS {
		c.DNS[i] = u(v, p)
	}

	for i, v := range c.DNSTCP {
		c.DNSTCP[i] = u(v, p)
	}
}

// Describes a Layer 4 service
type Service struct {
	// The service name - should be a short identifier, suitable for using as a Prometheus label value
	Name string `json:"name,omitempty"`

	// A short description of the service
	Description string `json:"description,omitempty"`

	// The minimum number of real servers which need to be health to consider this service viable
	Need uint16 `json:"need,omitempty"`

	// The set of backend server addresses and corresponding healthchecks which comprise this service
	//RIPs map[string]Checks `json:"rips,omitempty"`
	RIPs map[ipd]Checks `json:"rips,omitempty"`

	// If set to true, the backend selection algorithm will not include layer 4 port numbers
	Sticky bool `json:"sticky,omitempty"`

	// Experimental/Unimplemented
	Leastconns bool `json:"leastconns,omitempty"`

	Scheduler types.Scheduler `json:"scheduler"`

	DSR bool `json:"dsr,omitempty"`
}

// Describes a Layer 4 service
type Service2 struct {
	// The service name - should be a short identifier, suitable for using as a Prometheus label value
	Name string `json:"name,omitempty"`

	// A short description of the service
	Description string `json:"description,omitempty"`

	// The minimum number of real servers which need to be health to consider this service viable
	Need uint16 `json:"need,omitempty"`

	// The set of backend server addresses and corresponding healthchecks which comprise this service
	//RIPs map[string]Checks `json:"rips,omitempty"`
	Reals map[ipport]Real `json:"reals,omitempty"`

	// If set to true, the backend selection algorithm will not include layer 4 port numbers
	Sticky bool `json:"sticky,omitempty"`

	Scheduler types.Scheduler `json:"scheduler"`
}

// Route Health Injection configration. Describes BGP peers and
// parameters to advertise healthy virtual IP addresses to network
// infrastructure
type RHI struct {
	// The local Autonomous sytem number to use when forming a BGP
	// session
	AS_Number uint16 `json:"as_number,omitempty"`

	// The desired hold timer
	Hold_Time uint16 `json:"hold_time,omitempty"`

	// A list of host names or addresses to form BGP sessions with
	Peers []string `json:"peers,omitempty"`

	// A list of community attributes to announce along with VIPs in
	// network layer reachability information updates. represented as
	// <asn>:<value pairs>, eg.: "100:80", "65000:1234"

	Communities_ []community `json:"communities,omitempty"`

	// Listen for incoming connections on port 179
	Listen bool `json:"listen,omitempty"`
}

// Returns a list of uint32 values representing configured BGP community attributes
func (r *RHI) Communities() []uint32 {
	var c []uint32
	for _, v := range r.Communities_ {
		c = append(c, uint32(v))
	}
	return c
}

// Load balancer configuration
type Config struct {
	// Two level dictionary of virual IP addresses and Layer 4
	// protocol/port number of services provided by the balancer
	//VIPs map[string]map[string]Service `json:"vips,omitempty"`

	Services map[ipp]Service2 `json:"services,omitempty"`

	// VLAN ID to subnet mappings
	VLANs map[uint16]string `json:"vlans,omitempty"`

	// Route Health Injection parameters
	RHI RHI `json:"rhi,omitempty"`

	// Length of time to wait for services to settle before
	// advertising route (should perhaps move to RHI)
	Learn uint16 `json:"learn,omitempty"`

	// Address to listen on for HTTP console/metrics server
	Webserver string `json:"webserver,omitempty"`

	// Address to listen on for multicast session announcements
	Multicast string `json:"multicast,omitempty"`
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

	return &config, nil
}

type community uint32

func (c *community) MarshalJSON() ([]byte, error) {
	return []byte(`"` + fmt.Sprintf("%d:%d", (*c>>16), (*c&0xffff)) + `"`), nil
}

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

type ipport struct {
	IP   types.IP4
	Port uint16
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
	return []byte(fmt.Sprintf("%s:%d", i.IP, i.Port)), nil
}

func (i *ipport) UnmarshalText(data []byte) error {

	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)(|:(\d+))$`)

	m := re.FindStringSubmatch(string(data))

	if len(m) != 4 {
		return errors.New("Badly formed ip:port")
	}

	ip, ok := types.ParseIP(m[1])

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

/**********************************************************************/
type ipd struct {
	IP       types.IP4
	Port     uint16
	Disabled bool
}

func (i *ipd) MarshalJSON() ([]byte, error) {
	text, err := i.MarshalText()

	if err != nil {
		return nil, err
	}

	return []byte(`"` + string(text) + `"`), nil
}

func (i *ipd) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("Badly formed ip:port")
	}

	return i.UnmarshalText(data[1 : l-1])
}

func (i ipd) MarshalText() ([]byte, error) {
	if i.Disabled {
		return []byte(fmt.Sprintf("%s:%d!", i.IP, i.Port)), nil
	}
	return []byte(fmt.Sprintf("%s:%d", i.IP, i.Port)), nil
}

func (i *ipd) UnmarshalText(data []byte) error {

	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)(|:(\d+))(!?)$`)

	m := re.FindStringSubmatch(string(data))

	if len(m) != 5 {
		return errors.New("Badly formed ip:port")
	}

	ip, ok := types.ParseIP(m[1])

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

	if m[4] != "" {
		i.Disabled = true
	}

	return nil
}

/**********************************************************************/

type ipp struct {
	IP       types.IP4
	Port     uint16
	Protocol uint8
}

func (i *ipp) MarshalJSON() ([]byte, error) {
	text, err := i.MarshalText()

	if err != nil {
		return nil, err
	}

	return []byte(`"` + string(text) + `"`), nil
}

func (i *ipp) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("Badly formed ip:port")
	}

	return i.UnmarshalText(data[1 : l-1])
}

func (i ipp) MarshalText() ([]byte, error) {

	var p string

	switch i.Protocol {
	case 6:
		p = "tcp"
	case 17:
		p = "udp"
	default:
		return nil, errors.New("Invalid protocol")
	}

	return []byte(fmt.Sprintf("%s:%d:%s", i.IP, i.Port, p)), nil
}

func (i *ipp) UnmarshalText(data []byte) error {

	text := string(data)

	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+):(\d+):(tcp|udp)$`)

	m := re.FindStringSubmatch(text)

	if len(m) != 4 {
		return errors.New("Badly formed ip:port:protocol - " + text)
	}

	ip, ok := types.ParseIP(m[1])

	if !ok {
		return errors.New("Badly formed ip:port:protocol - IP" + text)
	}

	i.IP = ip

	port, err := strconv.Atoi(m[2])
	if err != nil {
		return err
	}

	if port < 0 || port > 65535 {
		return errors.New("Badly formed ip:port:protocol, port out of rance 0-65535 - " + text)
	}

	i.Port = uint16(port)

	switch m[3] {
	case "tcp":
		i.Protocol = 6
	case "udp":
		i.Protocol = 17
	default:
		return errors.New("Badly formed ip:port:protocol, tcp/udp - " + text)
	}

	return nil
}

/**********************************************************************/

type method string

func (m *method) MarshalJSON() ([]byte, error) {
	text, err := m.MarshalText()

	if err != nil {
		return nil, err
	}

	return []byte(`"` + string(text) + `"`), nil
}

func (m *method) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("Bad method")
	}

	return m.UnmarshalText(data[1 : l-1])
}

func (m method) MarshalText() ([]byte, error) {

	return []byte(m), nil
}

func (m *method) UnmarshalText(data []byte) error {

	text := string(data)

	switch text {
	case "":
		fallthrough
	case "GET":
		fallthrough
	case "HEAD":
		*m = method(data)
	default:
		return errors.New("Bad method: " + text)
	}

	return nil
}

func (m *method) String() string {
	return string(*m)
}
