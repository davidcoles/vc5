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
	//"io"
	//"net"
	//"time"
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
const COMMUNITIES = 8

const AS_SET = 1
const AS_SEQUENCE = 2

const HOLD_TIMER_EXPIRED = 4
const CEASE = 6

const WTCR = 64  // (Well-known, Transitive, Complete, Regular length)
const WTCE = 80  // (Well-known, Transitive, Complete, Extended length)
const ONCR = 128 // (Optional, Non-transitive, Complete, Regular length)
const OTCR = 192 // (Optional, Transitive, Complete, Regular length)

// Optional/Well-known, Non-transitive/Transitive Complete/Partial Regular/Extended-length
// 128 64 32 16 8 4 2 1
// 0   1  0  1  0 0 0 0
// W   N  C  R  0 0 0 0
// O   T  P  E  0 0 0 0

type Peer struct {
	state       int
	peer        string
	port        uint16
	myip        [4]byte
	rid         [4]byte
	asn         uint16
	hold        uint16
	nlri        chan nlri
	logs        logger
	communities []uint32
}

type open struct {
	version byte
	as      uint16
	ht      uint16
	id      IP4
	op      []byte
}

type community struct {
	community_asn uint16
	community_val uint16
}

func (b open) String() string {
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

func (m message) String() string {
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

func (m message) headerise() []byte {
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

type message struct {
	mtype        byte
	open         open
	notification notification
	body         []byte
}

type nlri struct {
	ip IP4
	up bool
}

func (n *nlri) updown() string {
	if n.up {
		return "UP"
	}
	return "DOWN"
}

func newopen(d []byte) open {
	var o open
	o.version = d[0]
	o.as = (uint16(d[1]) << 8) | uint16(d[2])
	o.ht = (uint16(d[3]) << 8) | uint16(d[4])
	copy(o.id[:], d[5:9])
	o.op = d[10:]
	return o
}

type notification struct {
	code uint8
	sub  uint8
	data []byte
}

func (n notification) String() string {
	return fmt.Sprintf("[CODE:%d SUBCODE:%d DATA:%v]", n.code, n.sub, n.data)
}

func (n notification) message() []byte {
	return headerise(M_NOTIFICATION, n.bin())
}

func (n notification) bin() []byte {
	return append([]byte{n.code, n.sub}, n.data[:]...)
}
func newnotification(d []byte) notification {
	var n notification
	n.code = d[0]
	n.sub = d[1]
	n.data = d[2:]
	return n
}

func (b *open) bin() []byte {
	return []byte{b.version, byte(b.as >> 8), byte(b.as), byte(b.ht >> 8), byte(b.ht), b.id[0], b.id[1], b.id[2], b.id[3], 0}
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

	return p
}

type logger interface {
	EMERG(...interface{})
	ALERT(...interface{})
	CRIT(...interface{})
	ERR(...interface{})
	WARNING(...interface{})
	NOTICE(...interface{})
	INFO(...interface{})
	DEBUG(...interface{})
}

type Logger struct {
}

func (l *Logger) EMERG(e ...interface{})   { _debug(e...) }
func (l *Logger) ALERT(e ...interface{})   { _debug(e...) }
func (l *Logger) CRIT(e ...interface{})    { _debug(e...) }
func (l *Logger) ERR(e ...interface{})     { _debug(e...) }
func (l *Logger) WARNING(e ...interface{}) { _debug(e...) }
func (l *Logger) NOTICE(e ...interface{})  { _debug(e...) }
func (l *Logger) INFO(e ...interface{})    { _debug(e...) }
func (l *Logger) DEBUG(e ...interface{})   { _debug(e...) }

//func Session(peer string, myip [4]byte, rid [4]byte, asn uint16, hold uint16, wait chan bool) *Peer {
//	return Session_(peer, myip, rid, asn, hold, wait, nil)
//}
func Session(peer string, myip [4]byte, rid [4]byte, asn uint16, hold uint16, communities []uint32, wait chan bool, logs logger) *Peer {
	if rid == [4]byte{0, 0, 0, 0} {
		rid = myip
	}

	if logs == nil {
		logs = &Logger{}
	}

	b := Peer{nlri: make(chan nlri), peer: peer, port: 179, myip: myip, rid: rid, asn: asn, hold: hold, logs: logs, communities: communities}

	go b.session(wait)

	return &b
}

func (b *Peer) Close() {
	close(b.nlri)
}

func (b *Peer) NLRI(ip IP4, up bool) {
	b.nlri <- nlri{ip: ip, up: up}
}

func bgpupdate(myip IP4, asn uint16, external bool, comm []uint32, nlri ...nlri) []byte {

	var withdrawn []byte
	var advertise []byte

	status := make(map[IP4]bool)

	// eliminate any bounces
	for _, r := range nlri {
		status[r.ip] = r.up
	}

	for k, v := range status {
		if v {
			advertise = append(advertise, 32, k[0], k[1], k[2], k[3]) // 32 bit prefix
		} else {
			withdrawn = append(withdrawn, 32, k[0], k[1], k[2], k[3]) // 32 bit prefix
		}
	}

	lp := 128 //LOCAL_PREF

	// <attribute type, attribute length, attribute value> [data ...]
	// (Well-known, Transitive, Complete, Regular length), 1(ORIGIN), 1(byte), 0(IGP)
	origin := []byte{WTCR, ORIGIN, 1, IGP}

	// (Well-known, Transitive, Complete, Regular length). 2(AS_PATH), 0(bytes, if iBGP - may get updated)
	as_path := []byte{WTCR, AS_PATH, 0}
	if external {
		// Each AS path segment is represented by a triple <path segment type, path segment length, path segment value>
		as_sequence := []byte{AS_SEQUENCE, 1} // AS_SEQUENCE(2), 1 ASN
		as_sequence = append(as_sequence, htons(asn)...)
		as_path = append(as_path, as_sequence...)
		as_path[2] = byte(len(as_sequence)) // update length field
	}

	// (Well-known, Transitive, Complete, Regular length), NEXT_HOP(3), 4(bytes)
	next_hop := append([]byte{WTCR, NEXT_HOP, 4}, myip[:]...)

	// (Well-known, Transitive, Complete, Regular length), LOCAL_PREF(5), 4 bytes
	local_pref := append([]byte{WTCR, LOCAL_PREF, 4}, htonl(uint32(lp))...)

	comms := []byte{}
	for k, v := range comm {
		if k < 60 { // should implement extended length
			c := htonl(v)
			comms = append(comms, c[:]...)
		}
	}

	// (Optional, Transitive, Complete, Regular length), COMMUNITIES(8), 4 bytes
	communities := append([]byte{OTCR, COMMUNITIES, uint8(len(comms))}, comms...)

	path_attributes := []byte{}
	path_attributes = append(path_attributes, origin...)
	path_attributes = append(path_attributes, as_path...)
	path_attributes = append(path_attributes, next_hop...)
	path_attributes = append(path_attributes, local_pref...)
	if len(comm) > 0 {
		path_attributes = append(path_attributes, communities...)
	}

	//   +-----------------------------------------------------+
	//   |   Withdrawn Routes Length (2 octets)                |
	//   +-----------------------------------------------------+
	//   |   Withdrawn Routes (variable)                       |
	//   +-----------------------------------------------------+
	//   |   Total Path Attribute Length (2 octets)            |
	//   +-----------------------------------------------------+
	//   |   Path Attributes (variable)                        |
	//   +-----------------------------------------------------+
	//   |   Network Layer Reachability Information (variable) |
	//   +-----------------------------------------------------+

	var update []byte
	update = append(update, htons(uint16(len(withdrawn)))...)
	update = append(update, withdrawn...)

	if len(advertise) > 0 {
		update = append(update, htons(uint16(len(path_attributes)))...)
		update = append(update, path_attributes...)
		update = append(update, advertise...)
	} else {
		update = append(update, 0, 0) // total path attribute length 0 as there is no nlri
	}

	return update
}
