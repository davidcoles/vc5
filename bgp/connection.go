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
	"io"
	"net"
	"sync"
	"time"
)

type myconn struct {
	C           chan message
	close       chan bool
	writer_exit chan bool
	reader_exit chan bool
	pending     chan bool
	conn        net.Conn

	mutex sync.Mutex
	out   []message
}

func new_connection(local net.IP, peer string) (*myconn, error) {

	dialer := net.Dialer{
		Timeout: 10 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP:   local,
			Port: 0,
		},
	}

	conn, err := dialer.Dial("tcp", peer+":179")

	if err != nil {
		return nil, err
	}

	c := &myconn{
		C:           make(chan message),
		close:       make(chan bool),
		writer_exit: make(chan bool),
		reader_exit: make(chan bool),
		pending:     make(chan bool, 1),
		conn:        conn,
	}

	go c.writer()
	go c.reader()

	return c, nil
}

func (c *myconn) Close() {
	close(c.close)
}

func (c *myconn) shift() (message, bool) {
	c.mutex.Lock()
	c.mutex.Unlock()

	var m message

	if len(c.out) < 1 {
		return m, false
	}

	m = c.out[0]
	c.out = c.out[1:]

	select {
	case c.pending <- true: // more messages
	default:
	}

	return m, true
}

func (c *myconn) write(m message) {
	c.mutex.Lock()
	c.mutex.Unlock()

	c.out = append(c.out, m)

	select {
	case c.pending <- true:
	default:
	}
}

func (c *myconn) writer() {
	defer close(c.writer_exit)
	defer c.conn.Close()

	for {
		// if the peer closes the connection then the reader encounters an error and exits (c.reader_exit)
		// if the user asks to close the connection c.close is triggered

		select {
		case <-c.close:
			return
		case <-c.reader_exit:
			return
		case <-c.pending: // continue
		}

	drain:
		m, ok := c.shift()

		if ok {
			c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))

			_, err := c.conn.Write(m.headerise())
			if err != nil {
				return
			}
			goto drain
		}
	}
}

func (c *myconn) reader() {

	defer close(c.reader_exit)
	defer close(c.C)

	for {
		// try to read a message
		// if the writer side encounders an error, it will exit and close the connction, causing an error here
		// if the user asks to close the connection upstream then writer will exit, closing the net connection (error here)

		var header [19]byte

		n, e := io.ReadFull(c.conn, header[:])
		if n != len(header) || e != nil {
			//fmt.Println("********************", n, e)
			return
		}

		for _, b := range header[0:16] {
			if b != 0xff {
				return
			}
		}

		length := int(header[16])<<8 + int(header[17])
		mtype := header[18]

		if length < 19 || length > 4096 {
			return
		}

		length -= 19

		body := make([]byte, length)

		n, e = io.ReadFull(c.conn, body[:])
		if n != len(body) || e != nil {
			//fmt.Println("********************", n, e)
			return
		}

		var m message

		switch mtype {
		case M_OPEN:
			m = message{mtype: mtype, open: newopen(body)}
		case M_NOTIFICATION:
			m = message{mtype: mtype, notification: newnotification(body)}
		default:
			m = message{mtype: mtype, body: body}
		}

		//fmt.Println(m)

		select {
		case c.C <- m:
		case <-c.close: // user wants to close the connection
			return
		case <-c.writer_exit:
			return
		}
	}
}
