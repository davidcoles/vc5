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
	"os"
	"time"
)

// RECEIVED: OPEN:[VERSION:4 AS:65304 HOLD:240 ID:10.10.10.10 OPL:24 [{2 [1 4 0 1 0 1 2 0 64 2 0 0 65 4 0 0 255 24 70 0 71 0]}]]
// https://www.iana.org/assignments/capability-codes/capability-codes.xhtml#capability-codes-2
// 1 4 0 1 0 1     // Multiprotocol Extensions for BGP-4 -  AFI 01  SAFI 1
// 2 0             // Route Refresh Capability for BGP-4
// 64 2 0 0        // Graceful Restart Capability
// 65 4 0 0 255 24 // Support for 4-octet AS number capability
// 70 0            // Enhanced Route Refresh Capability
// 71 0            // Long-Lived Graceful Restart (LLGR) Capability

func htonl(h uint32) []byte {
	return []byte{byte(h >> 24), byte(h >> 16), byte(h >> 8), byte(h)}
}
func htons(h uint16) []byte {
	return []byte{byte(h >> 8), byte(h)}
}

func (p *Peer) debug(args ...interface{}) {
	var a []interface{}
	a = append(a, p.peer)
	a = append(a, args...)
	p.logs.DEBUG(a...)
}
func _debug(args ...interface{}) {
	_, ok := os.LookupEnv("DEBUG")
	if ok {
		fmt.Println(args...)
	}
}

func sleeper(n uint8) chan bool {
	c := make(chan bool)
	go func() {
		time.Sleep(time.Duration(n) * time.Second)
		close(c)
	}()
	return c
}

func slice(up map[IP4]bool) []nlri {
	ad := []nlri{}
	for k, _ := range up {
		ad = append(ad, nlri{ip: k, up: true})
	}
	return ad
}

func (p *Peer) session(wait chan bool) {

	nlri, done := p.connect(wait, nil)

	up := make(map[IP4]bool)

	for {
		select {
		case <-done:
			close(nlri)
			nlri, done = p.connect(sleeper(10), slice(up))

		case u, ok := <-p.nlri:
			if !ok {
				close(nlri)
				return
			}

			if u.up {
				up[u.ip] = true
			} else {
				delete(up, u.ip)
			}

			nlri <- u // won't block
		}
	}
}

func (p *Peer) connect(wait chan bool, initial []nlri) (chan nlri, chan bool) {
	nlri := make(chan nlri, 10000)
	done := make(chan bool)
	for _, n := range initial {
		nlri <- n
	}
	go p.bgp4fsm(wait, nlri, done)
	return nlri, done
}

func (p *Peer) bgp4fsm(wait chan bool, nlri chan nlri, done chan bool) {

	p.state = IDLE
	defer func() {
		p.state = IDLE
		close(done)
	}()

	pend := newpending(nlri)

	select {
	case <-wait: // wait for channel to close (before connecting)
	case <-pend.done: // short circuit if upstream is closed
		return
	}

	p.state = CONNECT

	conn, err := connection(p.myip, p.peer, p.port)

	if err != nil {
		return
	}

	defer close(conn.send)

	p.debug("CONNECTED:", p.peer)

	keep := make(chan bool)
	exit := make(chan bool)
	hold := make(chan bool)
	defer close(exit)

	var external bool = false
	var hold_timer *time.Timer
	var hold_time uint16 = p.hold

	select {
	case conn.send <- message{mtype: M_OPEN, open: open{version: 4, as: p.asn, ht: hold_time, id: p.rid}}:
		p.state = OPEN_SENT
	case <-conn.dead:
	case <-pend.done:
	}

	for {
		select {
		case <-conn.dead: // tcp connection died
			p.debug("TCP DIED", p.peer)
			return

		case <-pend.done: // tear down session
			p.debug("CLOSING", p.peer)
			select {
			case conn.send <- message{mtype: M_NOTIFICATION, notification: notification{code: CEASE}}:
			case <-conn.dead: // tcp connection died
			}
			return

		case <-hold:
			p.debug("HOLD TIMER EXPIRED", p.peer)
			select {
			case conn.send <- message{mtype: M_NOTIFICATION, notification: notification{code: HOLD_TIMER_EXPIRED}}:
			case <-conn.dead: // tcp connection died
			}
			return

		case <-pend.poll: // nrli update waiting
			if p.state == ESTABLISHED {
				select {
				case n := <-pend.nlri:
					select { // check for hold timer expiry here?
					case conn.send <- message{mtype: M_UPDATE, body: bgpupdate(p.myip, p.asn, external, p.communities, n)}:
						p.debug("ADVERTISING ", n.ip, "AS", n.updown(), "TO", p.peer)
					case <-conn.dead: // tcp connection died
					case <-pend.done: // tear down session
					}
				default: // fibbing? probably not needed now as channel is buffered
				}
			}

		case <-keep:
			if p.state == ESTABLISHED {
				select {
				case conn.send <- message{mtype: M_KEEPALIVE}:
				case <-conn.dead: // tcp connection died
				case <-pend.done: // tear down session
				}
			}

		case m, ok := <-conn.recv:
			if !ok {
				p.debug("RECV CLOSED")
				return
			}

			if hold_timer != nil {
				hold_timer.Reset(time.Duration(hold_time) * time.Second)
			}

			if m.mtype == M_NOTIFICATION {
				p.debug("M_NOTIFICATION", m)
				return
			}

			switch p.state {
			case OPEN_SENT:
				switch m.mtype {
				case M_OPEN:
					p.state = OPEN_CONFIRM
					external = m.open.as != p.asn // iBGP or eBGP
					if m.open.ht == 0 || (m.open.ht >= 3 && m.open.ht < hold_time) {
						hold_time = m.open.ht
					}
					if hold_time > 0 {
						hold_timer = time.AfterFunc(time.Duration(hold_time)*time.Second, func() { close(hold) })
						p.debug("hold_timer", hold_time)
						defer hold_timer.Stop()
					}
					select {
					case conn.send <- message{mtype: M_KEEPALIVE}:
					case <-conn.dead: // tcp connection died
					case <-pend.done: // tear down session
					}

				default:
					p.debug("OPEN_SENT:", m)
				}

			case OPEN_CONFIRM:
				switch m.mtype {
				case M_KEEPALIVE:
					p.state = ESTABLISHED
					pend.wait = false // start alerting via poll
					go keepalive(keep, exit)
				default:
					p.debug("OPEN_CONFIRM:", m)
				}

			case ESTABLISHED:
				switch m.mtype {
				case M_KEEPALIVE:
				default:
					p.debug("ESTABLISHED:", m)
				}

			default:
				p.debug("DEFAULT:", p.state, m)
			}
		}
	}
}

type bgpconn struct {
	send chan message
	recv chan message
	dead chan bool
}

func connection(addr IP4, peer string, port uint16) (*bgpconn, error) {

	dialer := net.Dialer{
		Timeout: 10 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP(addr.String()),
			Port: 0,
		},
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", peer, port))

	//debug("CONNECTION", peer, port, err)

	if err != nil {
		return nil, err
	}

	send := make(chan message)
	recv := make(chan message)
	dead := make(chan bool)
	done := make(chan bool)

	c := bgpconn{send: send, recv: recv, dead: dead}

	go func() {
		// send
		defer close(done)
		for m := range send {
			if m.mtype != M_KEEPALIVE {
				//debug("SENDING:", m)
			}
			_, err := conn.Write(m.headerise())
			if err != nil {
				//debug("WRITE FAILED:", n)
				return
			}
		}
		//debug("SEND CLOSED")
	}()

	go func() {
		//recv
		defer close(recv)
		defer close(dead)

		for {
			m := readmessage(conn, done)
			if m == nil {
				return
			}
			if m.mtype != M_KEEPALIVE {
				//debug("RECEIVED:", *m)
			}
			select {
			case recv <- *m:
			case <-done:
				return
			}
		}
	}()

	return &c, nil
}

func readmessage(conn net.Conn, done chan bool) *message {

	select {
	case <-done:
		return nil
	default:
	}

	var header [19]byte

	n, e := io.ReadFull(conn, header[:])
	if n != len(header) || e != nil {
		return nil
	}

	for _, b := range header[0:16] {
		if b != 0xff {
			return nil
		}
	}

	length := int(header[16])<<8 + int(header[17])
	mtype := header[18]

	if length < 19 || length > 4096 {
		//fmt.Println("length out of bounds", length)
		return nil
	}

	length -= 19

	body := make([]byte, length)

	n, e = io.ReadFull(conn, body[:])
	if n != len(body) || e != nil {
		//fmt.Println(n, e)
		return nil
	}

	switch mtype {
	case M_OPEN:
		return &message{mtype: mtype, open: newopen(body)}
	case M_NOTIFICATION:
		return &message{mtype: mtype, notification: newnotification(body)}
	}

	return &message{mtype: mtype, body: body}
}

func keepalive(keep, done chan bool) {
	//debug("STARTING KEEPALIVE")
	for {
		time.Sleep(2 * time.Second)
		select {
		case keep <- true:
		case <-done:
			return
		}
	}
}

type pending_t struct {
	poll chan bool
	nlri chan nlri
	done chan bool
	wait bool
}

func newpending(in chan nlri) *pending_t {
	p := &pending_t{poll: make(chan bool), nlri: make(chan nlri, 1), done: make(chan bool)}

	go func() {
		defer close(p.done)
		var ri []nlri

		for {
			// stuff the outbound channel with any pending updates
			for blocked := false; !blocked && len(ri) > 0; {
				select {
				case p.nlri <- ri[0]:
					ri = ri[1:]
				default:
					blocked = true
				}
			}

			// if there are updates waiting to be read from channel ...
			if !p.wait && len(p.nlri) > 0 {
				select {
				case p.poll <- true: // let listener know
				case n, ok := <-in: // new updates ...
					if !ok {
						return
					}
					ri = append(ri, n)
				}
			} else {
				select {
				case n, ok := <-in:
					if !ok {
						return
					}
					ri = append(ri, n)
				}
			}
		}
	}()

	return p
}
