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
	"github.com/davidcoles/vc5/types"
	"net"
	"time"
)

type IP4 = types.IP4

/**********************************************************************/

type Pool struct {
	nlri chan map[IP4]bool
	peer chan []string
	wait chan bool

	Address     string
	ASN         uint16
	HoldTime    uint16
	Communities []uint32
	Peers       []string
	Listen      bool
	LocalPref   uint32
	MED         uint32
}

func (p *Pool) Open() bool {
	var rid IP4

	if p.Listen {
		go func() {
			for {
				bgpListen()
				time.Sleep(30 * time.Second)
			}
		}()
	}

	addr := net.ParseIP(p.Address)

	if addr == nil {
		return false
	}

	ip := addr.To4()

	if ip == nil {
		return false
	}

	copy(rid[:], ip[:])

	//b := &Pool{nlri: make(chan map[IP4]bool), peer: make(chan []string), wait: make(chan bool)}

	p.nlri = make(chan map[IP4]bool)
	p.peer = make(chan []string)
	p.wait = make(chan bool)

	go p.manage(rid, p.ASN, p.HoldTime, p.LocalPref, p.MED, p.Communities)
	p.peer <- p.Peers
	return true
}

func (p *Pool) Start() {
	if p.wait != nil {
		close(p.wait)
		p.wait = nil
	}
}

// func (b *Pool) NLRI(n map[IP4]bool) {
func (p *Pool) NLRI(n map[string]bool) {
	m := map[IP4]bool{}

	for k, v := range n {
		var ip types.IP4
		if ip.UnmarshalText([]byte(k)) == nil {
			m[ip] = v
		}
	}

	p.nlri <- m
}

func (b *Pool) Peer(p []string) {
	b.peer <- p
}

func diff(a, b map[IP4]bool) bool {
	for k, v := range a {
		if x, ok := b[k]; !ok || x != v {
			return true
		}
	}
	for k, v := range b {
		if x, ok := a[k]; !ok || x != v {
			return true
		}
	}
	return false
}

func bgpListen() {
	l, err := net.Listen("tcp", ":179")
	if err != nil {
		//logs.NOTICE("BGP4 listen failed", err)
		return
	}

	//logs.WARNING("Listening:", l)

	defer l.Close()

	for {
		conn, err := l.Accept()

		if err != nil {
			//logs.INFO("BGP4 connection failed", err)
		} else {
			go func(c net.Conn) {
				//logs.WARNING("Accepted conn:", c)
				defer c.Close()
				time.Sleep(time.Minute)
				//logs.WARNING("Quitting", c)
			}(conn)
		}
	}
}

func (b *Pool) manage(rid [4]byte, asn uint16, hold uint16, lp uint32, med uint32, communities []uint32) {

	nlri := map[IP4]bool{}
	peer := map[string]*Peer{}

	for {
		select {
		case n := <-b.nlri:

			if !diff(n, nlri) {
				break
			}

			for _, v := range peer {
				for ip, up := range n {
					v.NLRI(IP4(ip), up)
				}
				for ip, up := range nlri {
					if _, ok := n[ip]; !ok && up {
						v.NLRI(IP4(ip), false)
					}
				}
			}

			nlri = n

		case p := <-b.peer:

			m := map[string]*Peer{}

			for _, s := range p {

				if v, ok := peer[s]; ok {
					m[s] = v
					delete(peer, s)
				} else {
					h := hold
					if h == 0 {
						h = 4
					}

					v = Session(s, rid, rid, asn, h, lp, med, communities, b.wait, nil)
					m[s] = v
					for ip, up := range nlri {
						v.NLRI(IP4(ip), up)
					}
				}
			}

			for _, v := range peer {
				//logger.NOTICE("peers", "close", k, v)
				v.Close()
			}

			peer = m
		}
	}
}
