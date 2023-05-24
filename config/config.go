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
// configuration which can be unmarshalled from a JSON file at
// runtime. It is expected that a separate, human-editable, format
// would be processed to for the JSON representation.
package config

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"

	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4
type L4 = types.L4
type Check = types.Check
type Checks = types.Checks

// Describes a Layer 4 service
type Service struct {
	// The service name - should be a short identifier, suitable for using as a Prometheus label value
	Name string `json:"name,omitempty"`

	// A short description of the service
	Description string `json:"description,omitempty"`

	// The minimum number of real servers which need to be health to consider this service viable
	Need uint16 `json:"need,omitempty"`

	// The set of backend server addresses and corresponding healthchecks which comprise this service
	RIPs map[IP4]Checks `json:"rips,omitempty"`

	// If set to true, the backend selection algorithm will not include layer 4 port numbers
	Sticky bool `json:"sticky,omitempty"`

	// Experimental/Unimplemented
	Leastconns bool `json:"leastconns,omitempty"`

	// Experimental/Unimplemented
	Fallback bool `json:"fallback,omitempty"`

	// Experimental/Unimplemented
	Local Checks `json:"local,omitempty"`
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

	// Community attributes to announce along with VIPs in network
	// layer reachability information updates
	Communities []community `json:"communities,omitempty"`

	// Listen for incoming connections on port 179
	Listen bool `json:"listen,omitempty"`
}

// Returns a list of uint32 values representing configured BGP community attributes
func (r *RHI) Community() []uint32 {
	var c []uint32
	for _, v := range r.Communities {
		c = append(c, uint32(v))
	}
	return c
}

// Load balancer configuration
type Config struct {
	// Two level dictionary of virual IP addresses and Layer 4
	// protocol/port number of services provided by the balancer
	VIPs map[IP4]map[L4]Service `json:"vips,omitempty"`

	// VLAN ID to subnet mappings
	VLANs map[uint16]string `json:"vlans,omitempty"`

	// Route Health Injection parameters
	RHI RHI `json:"rhi,omitempty"`

	// Length of time to wait for services to settle before
	// advertising route (should perhaps move to RHI)
	Learn uint16 `json:"learn,omitempty"`

	// Address to listen on for HTTP console/metrics server
	Webserver string `json:"webserver,omitempty"`
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
