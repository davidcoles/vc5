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

func (b *Peer) bgp4state(start chan bool, done chan bool) {

	out, fin := b.bgp4conn(start, nil)

	up := make(map[IP4]bool)

	for {
		select {
		case <-fin:
			close(out)
			out, fin = b.bgp4conn(sleeper(10), slice(up))

		case u := <-b.updates:
			if u.up {
				up[u.ip] = true
			} else {
				delete(up, u.ip)
			}
			out <- u
		case <-done:
			close(out)
			return
		}
	}
}

func (b *Peer) bgp4conn(start chan bool, ad []nlri) (chan nlri, chan bool) {
	ri := make(chan nlri, 10000)
	ok := make(chan bool)
	for _, n := range ad {
		ri <- n
	}
	go b.bgp4fsm(start, ri, ok)
	return ri, ok
}

func (b *Peer) bgp4fsm(start chan bool, ri chan nlri, ok chan bool) {

	keep := make(chan bool)
	exit := make(chan bool)
	defer close(exit)

	var external bool = false

	pend := newpending(ri)

	<-start

	b.state = IDLE

	defer func() {
		b.state = IDLE
		close(ok)
	}()

	b.state = CONNECT

	conn, err := connection(b.myip, b.peer, b.port)

	if err != nil {
		return
	}

	defer close(conn.send)

	fmt.Println("CONNECTED:", b.peer)

	select {
	case conn.send <- bgpmessage{mtype: M_OPEN, open: bgpopen{version: 4, as: b.asn, ht: 5, id: b.rid}}:
		b.state = OPEN_SENT
	case <-conn.dead:
	case <-pend.done:
	}

	for {
		select {
		case <-conn.dead: // tcp connection died
			fmt.Println("TCP DIED", b.peer)
			return

		case <-pend.done: // tear down session
			fmt.Println("CLOSING", b.peer)
			conn.send <- bgpmessage{mtype: M_NOTIFICATION, notification: bgpnotification{code: CEASE}}
			return

		case <-pend.poll: // nrli update waiting
			if b.state == ESTABLISHED {
				select {
				case n := <-pend.nlri:
					select {
					case conn.send <- bgpmessage{mtype: M_UPDATE, body: bgpupdate(b.myip, b.asn, external, []nlri{n})}:
					case <-conn.dead: // tcp connection died
					case <-pend.done: // tear down session
					}
				default: // fibbing?
				}
			}

		case <-keep:
			if b.state == ESTABLISHED {
				select {
				case conn.send <- bgpmessage{mtype: M_KEEPALIVE}:
				case <-conn.dead: // tcp connection died
				case <-pend.done: // tear down session
				}
			}

		case m, ok := <-conn.recv:
			if !ok {
				fmt.Println("RECV CLOSED")
				return
			}

			switch b.state {
			case OPEN_SENT:
				switch m.mtype {
				case M_OPEN:
					external = m.open.as != b.asn
					select {
					case conn.send <- bgpmessage{mtype: M_KEEPALIVE}:
						b.state = OPEN_CONFIRM
					case <-conn.dead: // tcp connection died
					case <-pend.done: // tear down session
					}
				default:
					fmt.Println("OPEN_SENT:", m)
				}

			case OPEN_CONFIRM:
				switch m.mtype {
				case M_KEEPALIVE:
					go keepalive(keep, exit)
					b.state = ESTABLISHED
				default:
					fmt.Println("OPEN_CONFIRM:", m)
				}

			case ESTABLISHED:
				switch m.mtype {
				case M_KEEPALIVE:
				default:
					fmt.Println("ESTABLISHED:", m)
				}

			default:
				fmt.Println("DEFAULT:", b.state, m)
			}
		}
	}
}

type bgpconn struct {
	send chan bgpmessage
	recv chan bgpmessage
	dead chan bool
}

func connection(addr IP4, peer string, port uint16) (*bgpconn, error) {

	dialer := net.Dialer{
		Timeout: 10 * time.Second,
		LocalAddr: &net.TCPAddr{
			//IP:   net.ParseIP(ipaddr),
			IP:   net.ParseIP(addr.String()),
			Port: 0,
		},
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", peer, port))

	fmt.Println("CONNECTION", peer, port, err)

	if err != nil {
		return nil, err
	}

	send := make(chan bgpmessage)
	recv := make(chan bgpmessage)
	dead := make(chan bool)
	done := make(chan bool)

	c := bgpconn{send: send, recv: recv, dead: dead}

	go func() {
		// send
		for m := range send {
			if m.mtype != M_KEEPALIVE {
				fmt.Println("SENDING:", m)
			}
			conn.Write(m.headerise())
		}
		fmt.Println("QUITTING")
		close(done)
	}()

	go func() {
		//recv
		defer close(recv)
		defer close(dead)

		for {
			m := bgp4readmessage(conn, done)
			if m == nil {
				return
			}
			if m.mtype != M_KEEPALIVE {
				fmt.Println("RECEIVED:", *m)
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

func bgp4readmessage(conn net.Conn, done chan bool) *bgpmessage {

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
			//fmt.Println("header not all 1s")
			return nil
		}
	}

	length := int(header[16])<<8 + int(header[17])
	mtype := header[18]

	//fmt.Println(header, length, mtype)

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

	//fmt.Println("RECV:", mtype, body)

	switch mtype {
	case M_OPEN:
		return &bgpmessage{mtype: mtype, open: newopen(body)}
	case M_NOTIFICATION:
		return &bgpmessage{mtype: mtype, notification: newnotification(body)}
	}

	return &bgpmessage{mtype: mtype, body: body}
}

func keepalive(keep, done chan bool) {
	fmt.Println("STARTING KEEPALIVE")
	for {
		time.Sleep(1 * time.Second)
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
}

func newpending(in chan nlri) *pending_t {
	p := &pending_t{poll: make(chan bool), nlri: make(chan nlri), done: make(chan bool)}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		defer close(p.done)
		var ri []nlri

		for {
			if len(ri) > 0 {
				r := ri[0]
				select {
				case n, ok := <-in:
					if !ok {
						return
					}
					ri = append(ri, n)
				case <-ticker.C:
					select {
					case p.poll <- true:
					default:
					}
				case p.nlri <- r:
					ri = ri[1:]
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
