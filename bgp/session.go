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
	"net"
	"time"
)

func session(id IP, peer string, current Update) chan Update {

	updates := make(chan Update)

	go func() {
		ip := current.Parameters.SourceIP

		local := net.ParseIP(ip_string(ip))

		retry_time := 10 * time.Second

		timer := time.NewTimer(retry_time)
		timer.Stop()

		defer timer.Stop()

		connection, done := active(id, local, peer, current)

		defer func() {
			if connection != nil {
				close(connection)
			}
		}()

		for {
			if connection != nil { //active
				select {
				case <-done: // downstream closed - wait and re-establish
					connection = nil
					timer.Reset(retry_time)
				case c, ok := <-updates:
					if !ok {
						return
					}

					current.RIB = c.RIB
					if c.Parameters != nil {
						current.Parameters = c.Parameters
					}

					select {
					case connection <- current:
					case <-done: // downstream closed - wait and re-establish
						connection = nil
						timer.Reset(30 * retry_time)
					}
				}
			} else { //idle
				select {
				case c, ok := <-updates:
					if !ok {
						return
					}

					current.RIB = c.RIB
					if c.Parameters != nil {
						current.Parameters = c.Parameters
					}

				case <-timer.C:
					connection, done = active(id, local, peer, current)
				}
			}
		}
	}()

	return updates
}

func active(id IP, local net.IP, peer string, u Update) (chan Update, chan bool) {
	updates := make(chan Update)
	done := make(chan bool)

	go func() {

		ip := u.Parameters.SourceIP
		asn := u.Parameters.ASNumber
		ht := u.Parameters.HoldTime

		if ht < 3 {
			ht = 10
		}

		defer close(done) // let upstream know that the connection has failed/closed

		state := ACTIVE

		conn, err := new_connection(local, peer)

		if err != nil {
			return
		}

		state = CONNECT

		defer conn.Close()

		conn.write(openMessage(asn, ht, id))

		state = OPEN_SENT

		defer func() {
			state = IDLE
		}()

		hold_time_ns := time.Duration(ht) * time.Second
		hold_timer := time.NewTimer(hold_time_ns)
		defer hold_timer.Stop()

		keepalive_time_ns := hold_time_ns / 3
		keepalive_timer := time.NewTicker(keepalive_time_ns)
		defer keepalive_timer.Stop()

		var external bool

		for {
			select {
			case m, ok := <-conn.C:

				if !ok {
					return
				}

				hold_timer.Reset(hold_time_ns)

				switch m.mtype {
				case M_NOTIFICATION:
					// note why
					return

				case M_KEEPALIVE:
					if state == OPEN_SENT {
						conn.write(notificationMessage(FSM_ERROR, 0))
						return
					}

				case M_OPEN:
					if state != OPEN_SENT {
						conn.write(notificationMessage(FSM_ERROR, 0))
						return
					}

					if m.open.version != 4 {
						conn.write(notificationMessage(OPEN_ERROR, UNSUPPORTED_VERSION_NUMBER))
						return
					}

					if m.open.ht < 3 {
						conn.write(notificationMessage(OPEN_ERROR, UNNACEPTABLE_HOLD_TIME))
						return
					}

					if m.open.id == id {
						conn.write(notificationMessage(OPEN_ERROR, BAD_BGP_ID))
						return
					}

					if m.open.ht < ht {
						ht = m.open.ht
						hold_time_ns = time.Duration(ht) * time.Second
						keepalive_time_ns = hold_time_ns / 3
					}

					hold_timer.Reset(hold_time_ns)
					keepalive_timer.Reset(keepalive_time_ns)

					external = m.open.as != asn

					state = ESTABLISHED

					conn.write(keepaliveMessage())
					conn.write(updateMessage(ip, asn, u.Parameters, external, u.full()))

				case M_UPDATE:
					if state != ESTABLISHED {
						conn.write(notificationMessage(FSM_ERROR, 0))
						return
					}
					// we just ignore updates!

				default:
					conn.write(notificationMessage(MESSAGE_HEADER_ERROR, BAD_MESSAGE_TYPE))
				}

			case r, ok := <-updates:

				if !ok {
					//conn.write(notificationMessage(CEASE, ADMINISTRATIVE_SHUTDOWN))
					conn.write(shutdownMessage("That's all, folks!"))
					return
				}

				if r.Parameters == nil {
					r.Parameters = u.Parameters
				}

				if state == ESTABLISHED {

					nlris := r.updates(u)
					if len(nlris) != 0 {
						conn.write(updateMessage(ip, asn, r.Parameters, external, nlris))
					}
				}

				u = r

			case <-keepalive_timer.C:
				if state == ESTABLISHED {
					conn.write(keepaliveMessage())
				}

			case <-hold_timer.C:
				conn.write(notificationMessage(HOLD_TIMER_EXPIRED, 0))
				return
			}
		}
	}()

	return updates, done
}
