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

package bgp4

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
)

type IP = [4]byte

// type IP4 [4]byte
type IPNet net.IPNet

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

func ip_string(i IP) string {
	return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3])
}

func (i *IPNet) MarshalJSON() ([]byte, error) {
	return []byte(`"` + (*net.IPNet)(i).String() + `"`), nil
}

func (i *IPNet) UnmarshalJSON(data []byte) error {

	l := len(data)

	if l < 3 || data[0] != '"' || data[l-1] != '"' {
		return errors.New("Badly formed CIDR address")
	}

	return i.UnmarshalText(data[1 : l-1])
}

func (i *IPNet) UnmarshalText(data []byte) error {

	re := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

	s := string(data)

	if re.Match(data) {
		s += "/32"
	}

	_, ipnet, err := net.ParseCIDR(s)

	if err != nil {
		return err
	}

	*i = IPNet(*ipnet)

	return nil
}

type Community uint32

func (c *Community) MarshalJSON() ([]byte, error) {
	return []byte(`"` + fmt.Sprintf("%d:%d", (*c>>16), (*c&0xffff)) + `"`), nil
}

func (c *Community) UnmarshalJSON(data []byte) error {
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

	*c = Community(uint32(asn)<<16 | uint32(val))

	return nil
}

type Parameters struct {
	// only used at session start
	ASN      uint16 `json:"as_number"`
	HoldTime uint16 `json:"hold_time"`
	SourceIP IP     `json:"source_ip"`

	// can change during session
	MED         uint32      `json:"med"`
	LocalPref   uint32      `json:"local_pref"`
	Communities []Community `json:"communities"`
	Accept      []IPNet     `json:"accept"`
	Reject      []IPNet     `json:"reject"`
}

func (a *Parameters) Diff(b *Parameters) (r bool) {
	r = true

	if a.LocalPref != b.LocalPref ||
		a.MED != b.MED ||
		len(a.Communities) != len(b.Communities) {
		return
	}

	for i, c := range a.Communities {
		if b.Communities[i] != c {
			return
		}
	}

	return false
}
