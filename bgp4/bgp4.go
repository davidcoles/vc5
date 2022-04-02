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
const M_NOTIFICATION = 3
const M_KEEPALIVE = 4

const IGP = 0
const EGP = 1

const ORIGIN = 1
const AS_PATH = 2
const NEXT_HOP = 3
const LOCAL_PREF = 5

const AS_SET = 1
const AS_SEQUENCE = 2

const CEASE = 6

type BGP4 = Peer

type Peer struct {
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
	op      []byte
}

func (b bgpopen) String() string {
	op := b.op
	type param struct {
		t uint8
		v []byte
	}
	var p []param
	for len(op) > 2 {
		t := op[0]
		l := op[1]
		if 2+int(l) > len(op) {
			break
		}
		v := op[2 : 2+l]
		op = op[2+l:]
		p = append(p, param{t: t, v: v})
	}

	return fmt.Sprintf("[VERSION:%d AS:%d HOLD:%d ID:%s OPL:%d %v]", b.version, b.as, b.ht, b.id, len(b.op), p)
}

func (m bgpmessage) String() string {
	switch m.mtype {
	case M_OPEN:
		return "OPEN:" + m.open.String()
	case M_NOTIFICATION:
		return "NOTIFICATION:" + m.notification.String()
	case M_KEEPALIVE:
		return "KEEPALIVE"
	case M_UPDATE:
		return fmt.Sprintf("UPDATE:%v", m.body)
	}
	return fmt.Sprintf("%d:%v", m.mtype, m.body)
}

func (m bgpmessage) headerise() []byte {
	//conn.Write(headerise(M_OPEN, open.data()))
	switch m.mtype {
	case M_OPEN:
		return headerise(m.mtype, m.open.bin())
	case M_NOTIFICATION:
		return headerise(m.mtype, m.notification.bin())
	case M_KEEPALIVE:
		return headerise(m.mtype, []byte{})
	case M_UPDATE:
		return headerise(m.mtype, m.body)
	}
	return headerise(m.mtype, []byte{})
}

type bgpmessage struct {
	mtype        byte
	open         bgpopen
	notification bgpnotification
	body         []byte
}

type nlri struct {
	ip IP4
	up bool
}

func newopen(d []byte) bgpopen {
	var o bgpopen
	o.version = d[0]
	o.as = (uint16(d[1]) << 8) | uint16(d[2])
	o.ht = (uint16(d[3]) << 8) | uint16(d[4])
	copy(o.id[:], d[5:9])
	o.op = d[10:]
	return o
}

type bgpnotification struct {
	code uint8
	sub  uint8
	data []byte
}

func (n bgpnotification) String() string {
	return fmt.Sprintf("[CODE:%d SUBCODE:%d DATA:%v]", n.code, n.sub, n.data)
}

func (n bgpnotification) message() []byte {
	return headerise(M_NOTIFICATION, n.bin())
}

func (n bgpnotification) bin() []byte {
	return append([]byte{n.code, n.sub}, n.data[:]...)
}
func newnotification(d []byte) bgpnotification {
	var n bgpnotification
	n.code = d[0]
	n.sub = d[1]
	n.data = d[2:]
	return n
}

func (b *bgpopen) bin() []byte {
	return []byte{b.version, byte(b.as >> 8), byte(b.as), byte(b.ht >> 8), byte(b.ht), b.id[0], b.id[0], b.id[0], b.id[0], 0}
}

//func BGP4Start(peer string, myip [4]byte, rid [4]byte, asn uint16, start chan bool, done chan bool) *BGP4 {
func Session(peer string, myip [4]byte, rid [4]byte, asn uint16, start chan bool, done chan bool) *BGP4 {
	if rid == [4]byte{0, 0, 0, 0} {
		rid = myip
	}

	b := BGP4{updates: make(chan nlri, 100000), peer: peer, port: 179, myip: myip, rid: rid, asn: asn}

	//go b.BGP4State(start, done)
	go b.bgp4state(start, done)

	return &b
}

func (b *BGP4) NLRI(ip IP4, up bool) {
	b.updates <- nlri{ip: ip, up: up}
}

func (b *BGP4) _BGP4State(start chan bool, done chan bool) {
	<-start

	addr := b.myip
	ipaddr := fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])

	d := net.Dialer{
		Timeout: 10 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP(ipaddr),
			Port: 0,
		},
	}

	updates := make(chan nlri)

	// buffer between bgp and the calling app
	go func() {
		var buffer []nlri

		for {
			if len(buffer) > 0 {
				select {
				case <-done:
					return
				case n := <-b.updates:
					buffer = append(buffer, n)
				case updates <- buffer[0]:
					buffer = buffer[1:]
				}
			} else {
				select {
				case <-done:
					return
				case n := <-b.updates:
					buffer = append(buffer, n)
				}
			}
		}
	}()

	up := make(map[IP4]bool)

	ok := make(chan bool)
	ri := make(chan nlri)
	go b.BGP4Conn(d, ri, ok, done)
	//go b.bgp4conn(d, ri, ok, done)

	for {
		select {
		case <-ok:
			time.Sleep(10 * time.Second)
			ok = make(chan bool)
			ri = make(chan nlri, 1000)
			go b.BGP4Conn(d, ri, ok, done)
			//go b.bgp4conn(d, ri, ok, done)
			for k, _ := range up {
				select {
				case ri <- nlri{ip: k, up: true}:
				case <-ok:
				}
			}
		case u := <-updates:
			if u.up {
				up[u.ip] = true
			} else {
				delete(up, u.ip)
			}
			select {
			case ri <- u:
			case <-ok:
			}
		case <-done:
			return
		}
	}
}

func (b *BGP4) BGP4Conn(d net.Dialer, ri chan nlri, ok chan bool, done chan bool) {
	b.state = IDLE

	defer func() {
		b.state = IDLE
		close(ok)
	}()

	b.state = CONNECT

	conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", b.peer, b.port))

	fmt.Println("CONNECTION", b.peer, b.port, err)

	if err != nil {
		b.state = IDLE
		return
	}

	defer conn.Close()

	fmt.Println("CONNECTED:", b.peer)

	var open bgpopen
	open.version = 4
	open.as = b.asn
	open.ht = 5
	open.id = b.rid
	open.op = nil

	fmt.Println("SEND: OPEN:"+open.String(), open.bin())

	conn.Write(headerise(M_OPEN, open.bin()))

	b.state = OPEN_SENT

	msgs := make(chan bgpmessage, 100)
	keep := make(chan bool)

	var external bool = false

	// keepalive timer
	keepalive := func(d chan bool) {
		fmt.Println("STARTING KEEPALIVE")
		for {
			time.Sleep(1 * time.Second)
			select {
			case keep <- true:
			case <-d:
				return
			}
		}
	}

	go BGP4ReadMessages(conn, msgs, done)

	var pending []nlri

	for {
		select {
		case <-done: // program is exiting
			//conn.Write(headerise(M_NOTIFICATION, bgpnotification{code: 6}.bin()))
			conn.Write(bgpnotification{code: CEASE}.message())
			fmt.Println("CLOSING", b.peer)
			return

		case <-keep:
			if b.state == ESTABLISHED {
				conn.Write(headerise(M_KEEPALIVE, nil))
			}
		case n := <-ri:
			pending = append(pending, n)
			if b.state == ESTABLISHED {
				conn.Write(headerise(M_UPDATE, bgpupdate(b.myip, b.asn, external, pending)))
				pending = []nlri{}
			}
		case m, ok := <-msgs:
			if !ok {
				return
			}

			fmt.Println("RECV:", m)

			switch b.state {
			case OPEN_SENT:
				switch m.mtype {
				case M_OPEN:
					external = m.open.as != b.asn
					conn.Write(headerise(M_KEEPALIVE, nil))
					b.state = OPEN_CONFIRM
				}

			case OPEN_CONFIRM:
				switch m.mtype {
				case M_KEEPALIVE:
					go keepalive(done)
					b.state = ESTABLISHED
					conn.Write(headerise(M_UPDATE, bgpupdate(b.myip, b.asn, external, pending)))
					pending = []nlri{}
				}

			case ESTABLISHED:
				// whatevs
			}
		}
	}
}

func bgpupdate(ip IP4, as uint16, external bool, ri []nlri) []byte {
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

	lp := 128 //LOCAL_PREF

	// <attribute type, attribute length, attribute value> [data ...]
	// 64 = 0b 0100 0000 (Well-known, Transitive, Complete, Regular length), 1(ORIGIN), 1(byte), 0(IGP)
	origin := [4]byte{64, ORIGIN, 1, IGP}

	// 64 = 0b 0100 0000 (Well-known, Transitive, Complete, Regular length). 2(AS_PATH), 0(bytes - iBGP)
	as_path := []byte{64, AS_PATH, 0}
	if external {
		// Each AS path segment is represented by a triple <path segment type, path segment length, path segment value>
		as_sequence := []byte{AS_SEQUENCE, 1} // AS_SEQUENCE(2), 1 ASN
		as_sequence = append(as_sequence, []byte{byte(as >> 8), byte(as & 0xff)}...)
		as_path = append(as_path, as_sequence[:]...)
		as_path[2] = byte(len(as_sequence)) // update length field
	}

	// 0b 0100 0000 (Well-known, Transitive, Complete, Regular length), 3(NEXT_HOP, 4(bytes)
	next_hop := append([]byte{64, NEXT_HOP, 4}, ip[:]...)

	// 0b 0100 0000 (Well-known, Transitive, Complete, Regular length), LOCAL_PREF(5), 4 bytes
	local_pref := append([]byte{64, LOCAL_PREF, 4}, []byte{byte(lp >> 24), byte(lp >> 16), byte(lp >> 8), byte(lp)}...)

	var wr []byte
	var nlri []byte

	for _, ip := range withdraw {
		wr = append(wr, 32, ip[0], ip[1], ip[2], ip[3])
	}

	for _, ip := range advertise {
		nlri = append(nlri, 32, ip[0], ip[1], ip[2], ip[3])
	}

	pa := []byte{}
	pa = append(pa, origin[:]...)
	pa = append(pa, as_path[:]...)
	pa = append(pa, next_hop[:]...)
	pa = append(pa, local_pref[:]...)

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

func BGP4ReadMessages(conn net.Conn, c chan bgpmessage, done chan bool) {
	defer close(c)
	for {

		select {
		case <-done:
			return
		default:
			// carry on if done isn't closed
		}

		var header [19]byte

		n, e := io.ReadFull(conn, header[:])
		if n != len(header) || e != nil {
			fmt.Println(n, e)
			return
		}

		for _, b := range header[0:16] {
			if b != 0xff {
				//fmt.Println("header not all 1s")
				return
			}
		}

		length := int(header[16])<<8 + int(header[17])
		mtype := header[18]

		//fmt.Println(header, length, mtype)

		if length < 19 || length > 4096 {
			//fmt.Println("length out of bounds", length)
		}

		length -= 19

		body := make([]byte, length)

		n, e = io.ReadFull(conn, body[:])
		if n != len(body) || e != nil {
			//fmt.Println(n, e)
			return
		}

		//fmt.Println("RECV:", mtype, body)

		switch mtype {
		case M_OPEN:
			c <- bgpmessage{mtype: mtype, open: newopen(body)}
		case M_NOTIFICATION:
			c <- bgpmessage{mtype: mtype, notification: newnotification(body)}
		default:
			c <- bgpmessage{mtype: mtype, body: body}
		}
	}
}
