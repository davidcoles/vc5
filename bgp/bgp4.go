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

// https://datatracker.ietf.org/doc/html/rfc4271 - A Border Gateway Protocol 4 (BGP-4)
// https://datatracker.ietf.org/doc/html/rfc8203 - BGP Administrative Shutdown Communication
// https://datatracker.ietf.org/doc/html/rfc4486 - Subcodes for BGP Cease Notification Message

// https://datatracker.ietf.org/doc/html/rfc2918 - Route Refresh Capability for BGP-4

package bgp

import (
	"fmt"
	//"os"
)

func htonl(h uint32) []byte {
	return []byte{byte(h >> 24), byte(h >> 16), byte(h >> 8), byte(h)}
}
func htons(h uint16) []byte {
	return []byte{byte(h >> 8), byte(h)}
}

const (
	M_OPEN         = 1
	M_UPDATE       = 2
	M_NOTIFICATION = 3
	M_KEEPALIVE    = 4

	IGP = 0
	EGP = 1

	ORIGIN          = 1
	AS_PATH         = 2
	NEXT_HOP        = 3
	MULTI_EXIT_DISC = 4
	LOCAL_PREF      = 5
	COMMUNITIES     = 8

	AS_SET      = 1
	AS_SEQUENCE = 2

	// NOTIFICATION ERROR CODES
	MESSAGE_HEADER_ERROR = 1
	OPEN_ERROR           = 2
	HOLD_TIMER_EXPIRED   = 4
	FSM_ERROR            = 5
	CEASE                = 6

	// MESSAGE_HEADER_ERROR
	BAD_MESSAGE_TYPE = 3

	// OPEN_ERROR
	UNSUPPORTED_VERSION_NUMBER = 1
	BAD_BGP_ID                 = 3
	UNNACEPTABLE_HOLD_TIME     = 6

	// CEASE
	//ADMINISTRATIVE_SHUTDOWN = 2
	//ADMINISTRATIVE_RESET    = 4

	MAXIMUM_PREFIXES_REACHED        = 1
	ADMINISTRATIVE_SHUTDOWN         = 2
	PEER_DECONFIGURED               = 3
	ADMINISTRATIVE_RESET            = 4
	CONNECTION_REJECTED             = 5
	OTHER_CONFIGURATION_CHANGE      = 6
	CONNECTION_COLLISION_RESOLUTION = 7
	OUT_OF_RESOURCES                = 8

	WTCR = 64  // (Well-known, Transitive, Complete, Regular length)
	WTCE = 80  // (Well-known, Transitive, Complete, Extended length)
	ONCR = 128 // (Optional, Non-transitive, Complete, Regular length)
	OTCR = 192 // (Optional, Transitive, Complete, Regular length)
)

func note(code, sub uint8) string {
	var s string
	switch code {
	case MESSAGE_HEADER_ERROR:
		s = "MESSAGE_HEADER_ERROR"
		switch sub {
		case BAD_MESSAGE_TYPE:
			s += " - BAD_MESSAGE_TYPE"
		}
	case OPEN_ERROR:
		s = "OPEN_ERROR"
		switch sub {
		case UNSUPPORTED_VERSION_NUMBER:
			s += " - UNSUPPORTED_VERSION_NUMBER"
		case BAD_BGP_ID:
			s += " - BAD_BGP_ID"
		case UNNACEPTABLE_HOLD_TIME:
			s += " - UNNACEPTABLE_HOLD_TIME"
		}

	case FSM_ERROR:
		s = "FSM_ERROR"
	case HOLD_TIMER_EXPIRED:
		s = "HOLD_TIMER_EXPIRED"

	case CEASE:
		s = "CEASE"
		switch sub {
		case MAXIMUM_PREFIXES_REACHED:
			s += " - MAXIMUM_PREFIXES_REACHED"
		case ADMINISTRATIVE_SHUTDOWN:
			s += " - ADMINISTRATIVE_SHUTDOWN"
		case PEER_DECONFIGURED:
			s += " - PEER_DECONFIGURED"
		case ADMINISTRATIVE_RESET:
			s += " - ADMINISTRATIVE_RESET"
		case CONNECTION_REJECTED:
			s += " - CONNECTION_REJECTED"
		case OTHER_CONFIGURATION_CHANGE:
			s += " - OTHER_CONFIGURATION_CHANGE"
		case CONNECTION_COLLISION_RESOLUTION:
			s += " - CONNECTION_COLLISION_RESOLUTION"
		case OUT_OF_RESOURCES:
			s += " - OUT_OF_RESOURCES"
		}
	}
	return s
}

// Optional/Well-known, Non-transitive/Transitive Complete/Partial Regular/Extended-length
// 128 64 32 16 8 4 2 1
// 0   1  0  1  0 0 0 0
// W   N  C  R  0 0 0 0
// O   T  P  E  0 0 0 0

type open struct {
	version byte
	as      uint16
	ht      uint16
	id      IP
	op      []byte
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

func (n notification) reason() string {
	r := fmt.Sprintf("[%d:%d]", n.code, n.sub)
	s := note(n.code, n.sub)

	if s != "" {
		r += " " + s
	}

	if len(n.data) > 0 {
		r += " (" + string(n.data) + ")"
	}

	return r
}

/*

func _debug(args ...interface{}) {
	_, ok := os.LookupEnv("DEBUG")
	if ok {
		fmt.Println(args...)
	}
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
*/
