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

// A really stupid BGP4 implementation for avertising /32 addresses for load balancing

package bgp4

import (
	"fmt"
	"io"
	"net"
	"time"
)

type IP4 [4]byte

func (i IP4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3])
}

const IDLE = 0
const CONNECT = 1
const ACTIVE = 2
const OPEN_SENT = 3
const OPEN_CONFIRM = 4
const ESTABLISHED = 5

const M_OPEN = 1
const M_UPDATE = 2
const M_KEEPALIVE = 4

type BGP4 struct {
	state   int
	peer    string
	port    uint16
	myip    [4]byte
	rid     [4]byte
	asn     uint16
	updates chan nlri
}

type bgpopen struct {
	version byte
	as      uint16
	ht      uint16
	id      IP4
	opl     byte
}

type bgpmessage struct {
	mtype byte
	open  bgpopen
}

func newopen(d []byte) bgpopen {
	var o bgpopen
	o.version = d[0]
	o.as = (uint16(d[1]) << 8) | uint16(d[2])
	o.ht = (uint16(d[3]) << 8) | uint16(d[4])
	copy(o.id[:], d[5:9])
	o.opl = 0
	return o
}

func (b *bgpopen) data() []byte {
	var data [10]byte
	data[0] = b.version

	data[1] = byte(b.as >> 8)
	data[2] = byte(b.as & 0xff)

	data[3] = byte(b.ht >> 8)
	data[4] = byte(b.as & 0xff)

	data[5] = b.id[0]
	data[6] = b.id[1]
	data[7] = b.id[2]
	data[8] = b.id[3]

	data[9] = b.opl

	return data[:]
}

func BGP4Start(peer string, myip [4]byte, rid [4]byte, asn uint16) *BGP4 {
	var b BGP4
	b.updates = make(chan nlri, 100)
	b.peer = peer
	b.port = 179
	b.myip = myip
	b.rid = rid
	b.asn = asn

	if rid == [4]byte{0, 0, 0, 0} {
		b.rid = myip
	}

	go b.BGP4State()

	return &b
}

func (b *BGP4) NLRI(ip IP4, up bool) {
	b.updates <- nlri{ip: ip, up: up}
}

func (b *BGP4) BGP4State() {

	time.Sleep(10 * time.Second)

	d := net.Dialer{Timeout: 2 * time.Second}

	up := make(map[IP4]bool)
	ok := make(chan bool)
	ri := make(chan nlri)

	b.state = IDLE

	go b.BGP4Conn(d, ri, ok)

	for {
		select {
		case <-ok: // connection is closed - re-open
			b.state = IDLE
			time.Sleep(10 * time.Second)
			ok = make(chan bool)
			ri = make(chan nlri)
			go b.BGP4Conn(d, ri, ok)
			for k, _ := range up {
				ri <- nlri{ip: k, up: true}
			}
		case u := <-b.updates:
			if u.up {
				up[u.ip] = true
			} else {
				delete(up, u.ip)
			}
			ri <- u
		}
	}

}

type Peers struct {
	peers []*BGP4
}

func Manager(myip [4]byte, rid [4]byte, as uint16, peers []string) *Peers {
	var b Peers
	for _, p := range peers {
		b.peers = append(b.peers, BGP4Start(p, myip, rid, as))
	}
	return &b
}

func (b *Peers) NLRI(ip [4]byte, up bool) {
	for _, p := range b.peers {
		p.NLRI(ip, up)
	}
}

type nlri struct {
	ip IP4
	up bool
}

func (b *BGP4) BGP4Conn(d net.Dialer, ri chan nlri, ok chan bool) {
	defer close(ok)

	b.state = CONNECT

	conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", b.peer, b.port))

	if err != nil {
		return
	}

	defer conn.Close()

	fmt.Println("CONNECTED:", b.peer)

	var open bgpopen
	open.version = 4
	open.as = b.asn
	open.ht = 240
	open.id = b.rid
	open.opl = 0

	fmt.Println(open)

	conn.Write(headerise(M_OPEN, open.data()))

	b.state = OPEN_SENT

	msgs := make(chan bgpmessage, 100)
	keep := make(chan bool)

	go func() {
		for {
			time.Sleep(6 * time.Second)
			keep <- true
		}
	}()

	go BGP4ReadMessages(conn, msgs)

	var pending []nlri

	for {
		select {
		case <-keep:
			if b.state == ESTABLISHED {
				conn.Write(headerise(M_KEEPALIVE, nil))
			}
		case n := <-ri:
			pending = append(pending, n)
			if b.state == ESTABLISHED {
				conn.Write(headerise(M_UPDATE, bgpupdate(b.myip, pending)))
				pending = []nlri{}
			}
		case m, ok := <-msgs:
			if !ok {
				return
			}

			switch b.state {
			case OPEN_SENT:
				switch m.mtype {
				case M_OPEN:
					fmt.Println(m)
					conn.Write(headerise(M_KEEPALIVE, nil))
					b.state = OPEN_CONFIRM
				}

			case OPEN_CONFIRM:
				switch m.mtype {
				case M_KEEPALIVE:
					b.state = ESTABLISHED
					conn.Write(headerise(M_UPDATE, bgpupdate(b.myip, pending)))
					pending = []nlri{}
				}

			case ESTABLISHED:
				// whatevs
			}
		}
	}
}

func bgpupdate(ip IP4, ri []nlri) []byte {
	/*
	   +-----------------------------------------------------+
	   |   Withdrawn Routes Length (2 octets)                |
	   +-----------------------------------------------------+
	   |   Withdrawn Routes (variable)                       |
	   +-----------------------------------------------------+
	   |   Total Path Attribute Length (2 octets)            |
	   +-----------------------------------------------------+
	   |   Path Attributes (variable)                        |
	   +-----------------------------------------------------+
	   |   Network Layer Reachability Information (variable) |
	   +-----------------------------------------------------+
	*/

	var withdraw []IP4
	var advertise []IP4

	status := make(map[IP4]bool)

	for _, r := range ri {
		status[r.ip] = r.up
	}

	for k, v := range status {
		if v {
			advertise = append(advertise, k)
		} else {
			withdraw = append(withdraw, k)
		}
	}

	// <attribute type, attribute length, attribute value>
	var origin [4]byte
	origin[0] = 64 // 0b 0100 0000 (Well-known, Transitive, Complete, Regular length)
	origin[1] = 1  // ORIGIN
	origin[2] = 1  // 1 byte
	origin[3] = 0  // IGP

	var as_path [3]byte
	as_path[0] = 64 // 0b 0100 0000 (Well-known, Transitive, Complete, Regular length)
	as_path[1] = 2  // AS_PATH
	as_path[2] = 0  // 0 bytes - iBGP, not needed

	var next_hop [7]byte
	next_hop[0] = 64 // 0b 0100 0000 (Well-known, Transitive, Complete, Regular length)
	next_hop[1] = 3  // NEXT_HOP
	next_hop[2] = 4  // 4 bytes
	next_hop[3] = ip[0]
	next_hop[4] = ip[1]
	next_hop[5] = ip[2]
	next_hop[6] = ip[3]

	lp := 128
	var local_pref [7]byte
	local_pref[0] = 64 // 0b 0100 0000 (Well-known, Transitive, Complete, Regular length)
	local_pref[1] = 5  // LOCAL_PREF
	local_pref[2] = 4  // 4 bytes
	local_pref[3] = byte((lp >> 24) & 0xff)
	local_pref[4] = byte((lp >> 16) & 0xff)
	local_pref[5] = byte((lp >> 8) & 0xff)
	local_pref[6] = byte((lp >> 0) & 0xff)

	var wr []byte
	var nlri []byte

	for _, ip := range withdraw {
		wr = append(wr, 32, ip[0], ip[1], ip[2], ip[3])
	}

	for _, ip := range advertise {
		nlri = append(nlri, 32, ip[0], ip[1], ip[2], ip[3])
	}

	pa := make([]byte, len(origin)+len(as_path)+len(next_hop)+len(local_pref))
	copy(pa[0:], origin[:])
	copy(pa[(len(origin)):], as_path[:])
	copy(pa[(len(origin)+len(as_path)):], next_hop[:])
	copy(pa[(len(origin)+len(as_path)+len(next_hop)):], local_pref[:])

	u := make([]byte, 4+len(wr)+len(pa)+len(nlri))

	u[0] = byte(len(wr) >> 8)
	u[1] = byte(len(wr) & 0xff)

	o := 2

	copy(u[o:], wr[:])

	o += len(wr)

	u[o+0] = byte(len(pa) >> 8)
	u[o+1] = byte(len(pa) & 0xff)

	o += 2

	copy(u[o:], pa[:])

	o += len(pa)

	copy(u[o:], nlri[:])

	return u
}

func headerise(t byte, d []byte) []byte {
	l := 19 + len(d)
	p := make([]byte, l)
	for n := 0; n < 16; n++ {
		p[n] = 0xff
	}

	p[16] = byte(l >> 8)
	p[17] = byte(l & 0xff)
	p[18] = t

	copy(p[19:], d)

	//fmt.Println("XMIT", t, d)

	return p
}

func BGP4ReadMessages(conn net.Conn, c chan bgpmessage) {
	defer close(c)
	for {
		var header [19]byte

		n, e := io.ReadFull(conn, header[:])
		if n != len(header) || e != nil {
			fmt.Println(n, e)
			return
		}

		for _, b := range header[0:16] {
			if b != 0xff {
				fmt.Println("header not all 1s")
				return
			}
		}

		length := int(header[16])<<8 + int(header[17])
		mtype := header[18]

		//fmt.Println(header, length, mtype)

		if length < 19 || length > 4096 {
			fmt.Println("length out of bounds", length)
		}

		length -= 19

		body := make([]byte, length)

		n, e = io.ReadFull(conn, body[:])
		if n != len(body) || e != nil {
			fmt.Println(n, e)
			return
		}

		switch mtype {
		case M_OPEN:
			c <- bgpmessage{mtype: mtype, open: newopen(body)}
		default:
			c <- bgpmessage{mtype: mtype}
		}
	}

}
