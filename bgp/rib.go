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

package bgp

import (
	"net"
)

type Update struct {
	RIB        []IP
	Parameters Parameters
}

func (r *Update) adjRIBOutString() (out []string) {
	for _, p := range r.Parameters.Filter(r.RIB) {
		out = append(out, ip_string(p))
	}
	return
}

func (r *Update) adjRIBOut() []IP {
	return r.Parameters.Filter(r.RIB)
}

func (r *Update) Filter() []IP {
	return r.Parameters.Filter(r.RIB)
}

func (p *Parameters) Filter(dest []IP) []IP {
	var pass []IP

filter:
	for _, i := range dest {

		ip := net.ParseIP(ip_string(i))

		if ip == nil {
			continue
		}

		for _, ipnet := range p.Accept {
			n := net.IPNet(ipnet)
			if n.Contains(ip) {
				pass = append(pass, i)
				continue filter
			}
		}

		for _, ipnet := range p.Reject {
			n := net.IPNet(ipnet)
			if n.Contains(ip) {
				continue filter
			}
		}

		pass = append(pass, i)
	}

	return pass
}

func Filter(dest []IP, filter []IP) []IP {

	reject := map[IP]bool{}

	if len(filter) == 0 {
		return dest
	}

	for _, i := range filter {
		reject[i] = true
	}

	var o []IP

	for _, i := range dest {
		if _, rejected := reject[i]; !rejected {
			o = append(o, i)
		}
	}

	return o
}

func (r *Update) full() map[IP]bool {
	n := map[IP]bool{}
	for _, ip := range r.adjRIBOut() {
		n[ip] = true
	}
	return n
}

func advertise(r []IP) map[IP]bool {
	n := map[IP]bool{}
	for _, ip := range r {
		n[ip] = true
	}
	return n
}

func to_string(in []IP) (out []string) {
	for _, p := range in {
		out = append(out, ip_string(p))
	}
	return
}

func (r Update) Copy() Update {
	var rib []IP

	for _, x := range r.RIB {
		rib = append(rib, x)
	}

	return Update{RIB: rib, Parameters: r.Parameters}
}

func (u *Update) Source() net.IP {
	return net.ParseIP(ip_string(u.Parameters.SourceIP))
}

func (c *Update) updates(p Update) (uint64, uint64, map[IP]bool) {
	nrli := map[IP]bool{}

	var advertise uint64
	var withdraw uint64

	var vary bool = c.Parameters.Diff(p.Parameters)

	curr := map[IP]bool{}
	prev := map[IP]bool{}

	for _, ip := range c.adjRIBOut() {
		curr[ip] = true
	}

	for _, ip := range p.adjRIBOut() {
		prev[ip] = true
	}

	for ip, _ := range curr {
		_, ok := prev[ip] // if didn't exist in previous rib, or params have changed then need to advertise
		if !ok || vary {
			advertise++
			nrli[ip] = true
		}
	}

	for ip, _ := range prev {
		_, ok := curr[ip] // if not in current rib then need to withdraw
		if !ok {
			withdraw++
			nrli[ip] = false
		}
	}

	return advertise, withdraw, nrli
}

func RIBSDiffer(a, b []IP) bool {

	x := map[IP]bool{}
	for _, i := range a {
		x[i] = true
	}

	y := map[IP]bool{}
	for _, i := range b {
		y[i] = true
	}

	if len(y) != len(y) {
		return true
	}

	for i, _ := range x {
		_, ok := y[i]
		if !ok {
			return true
		}
		delete(y, i)
	}

	return len(y) != 0
}
