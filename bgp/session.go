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
	"time"
)

const (
	IDLE         = "IDLE"
	ACTIVE       = "ACTIVE"
	CONNECT      = "CONNECT"
	OPEN_SENT    = "OPEN_SENT"
	OPEN_CONFIRM = "OPEN_CONFIRM"
	ESTABLISHED  = "ESTABLISHED"
)

type Status struct {
	State             string
	UpdateCalculation time.Duration `json:"update_calculation_ms"`
	Advertised        uint64
	Withdrawn         uint64
	AdjRIBOut         []string
	Prefixes          int
	Attempts          uint64
	Connections       uint64
	Established       uint64
	LastError         string
	HoldTime          uint16
	LocalASN          uint16
	RemoteASN         uint16
}

type Session struct {
	c      chan Update
	p      Parameters
	r      []IP
	status Status
}

func NewSession(id IP, peer string, p Parameters, r []IP) *Session {
	s := &Session{p: p, r: r}
	s.c = session(id, peer, Update{RIB: r, Parameters: p}, &(s.status))
	return s

}

func (s *Session) Status() Status {
	return s.status
}

func (s *Session) RIB(r []IP) {
	s.r = r
	s.c <- Update{RIB: s.r, Parameters: s.p}
}

func (s *Session) Configure(p Parameters) {
	s.p = p
	s.c <- Update{RIB: s.r, Parameters: s.p}
}

func (s *Session) Close() {
	close(s.c)
}

func session(id IP, peer string, update Update, status *Status) chan Update {

	updates := make(chan Update, 100)

	go func() {

		retry_time := 10 * time.Second

		timer := time.NewTimer(retry_time)
		timer.Stop()

		defer timer.Stop()

		connection, done := active(id, peer, update, status)

		defer func() {
			if connection != nil {
				close(connection)
			}
		}()

		var ok bool

		for {
			if connection != nil { //active
				select {
				case <-done: // downstream closed - wait and re-establish
					close(connection)
					connection = nil
					timer.Reset(retry_time)
					println(peer, status.LastError)

				case update, ok = <-updates:
					if !ok {
						return
					}

					select {
					case connection <- update:
					case <-done: // downstream closed - wait and re-establish
						close(connection)
						connection = nil
						timer.Reset(retry_time)
						println(peer, status.LastError)
					default: // updates have backed up channel (unlikely, but possible)
						close(connection)
						connection = nil
						timer.Reset(retry_time)
						status.LastError = "Technical difficulties"
					}
				}
			} else { // idle
				select {
				case update, ok = <-updates:
					if !ok {
						return
					}

				case <-timer.C:
					connection, done = active(id, peer, update, status)
				}
			}
		}
	}()

	return updates
}

func active(id IP, peer string, u Update, status *Status) (chan Update, chan bool) {
	updates := make(chan Update)
	done := make(chan bool)

	go func() {

		asn := u.Parameters.ASNumber
		ht := u.Parameters.HoldTime
		ip := u.Parameters.SourceIP

		if ht < 3 {
			ht = 10
		}

		defer func() {
			status.State = IDLE
			status.AdjRIBOut = nil
			status.Prefixes = 0
			status.Advertised = 0
			status.Withdrawn = 0
			status.HoldTime = 0
			close(done) // let upstream know that the connection has failed/closed
		}()

		status.State = ACTIVE

		status.Attempts++
		conn, err := new_connection(u.Source(), peer)

		if err != nil {
			status.LastError = err.Error()
			return
		}

		status.State = CONNECT
		status.Connections++

		defer conn.Close()

		conn.write(openMessage(asn, ht, id))

		status.State = OPEN_SENT

		hold_time_ns := time.Duration(ht) * time.Second
		hold_timer := time.NewTimer(hold_time_ns)
		defer hold_timer.Stop()

		keepalive_time_ns := hold_time_ns / 3
		keepalive_timer := time.NewTicker(keepalive_time_ns)
		defer keepalive_timer.Stop()

		var external bool

		update_stats := func(a, w uint64, d time.Duration, r []string) {
			status.Advertised += a
			status.Withdrawn += w
			status.UpdateCalculation = d / time.Millisecond
			status.AdjRIBOut = r
			status.Prefixes = len(r)
		}

		for {
			select {
			case m, ok := <-conn.C:

				if !ok {
					status.LastError = conn.Error
					return
				}

				hold_timer.Reset(hold_time_ns)

				switch m.mtype {
				case M_NOTIFICATION:
					// note why
					status.LastError = "NOTIFICATION" + m.notification.reason()
					return

				case M_KEEPALIVE:
					if status.State == OPEN_SENT {
						conn.write(notificationMessage(FSM_ERROR, 0))
						return
					}

				case M_OPEN:
					if status.State != OPEN_SENT {
						n := notificationMessage(FSM_ERROR, 0)
						conn.write(notificationMessage(FSM_ERROR, 0))
						status.LastError = "OPEN" + n.notification.reason()
						return
					}

					if m.open.version != 4 {
						n := notificationMessage(OPEN_ERROR, UNSUPPORTED_VERSION_NUMBER)
						conn.write(n)
						status.LastError = "OPEN" + n.notification.reason()
						return
					}

					if m.open.ht < 3 {
						n := notificationMessage(OPEN_ERROR, UNNACEPTABLE_HOLD_TIME)
						conn.write(n)
						status.LastError = "OPEN" + n.notification.reason()
						return
					}

					if m.open.id == id {
						n := notificationMessage(OPEN_ERROR, BAD_BGP_ID)
						conn.write(n)
						status.LastError = "OPEN" + n.notification.reason()
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

					status.State = ESTABLISHED
					status.LastError = ""
					status.Established++
					status.HoldTime = ht
					status.LocalASN = asn
					status.RemoteASN = m.open.as

					conn.write(keepaliveMessage())

					t := time.Now()
					aro := u.adjRIBOut()
					conn.write(updateMessage(ip, asn, u.Parameters, external, advertise(aro)))
					update_stats(uint64(len(aro)), 0, time.Now().Sub(t), to_string(aro))

				case M_UPDATE:
					if status.State != ESTABLISHED {
						n := notificationMessage(FSM_ERROR, 0)
						conn.write(n)
						status.LastError = status.State + "/UPDATE" + n.notification.reason()
						return
					}
					// we just ignore updates!

				default:
					n := notificationMessage(MESSAGE_HEADER_ERROR, BAD_MESSAGE_TYPE)
					conn.write(n)
					status.LastError = status.State + n.notification.reason()
				}

			case r, ok := <-updates:

				if !ok {
					//conn.write(notificationMessage(CEASE, ADMINISTRATIVE_SHUTDOWN))
					conn.write(shutdownMessage("That's all, folks!"))
					status.LastError = "Local shutdown"
					return
				}

				if status.State == ESTABLISHED {
					t := time.Now()
					a, w, nlris := r.updates(u)
					if len(nlris) != 0 {
						conn.write(updateMessage(ip, asn, r.Parameters, external, nlris))
					}
					update_stats(a, w, time.Now().Sub(t), r.adjRIBOutString())
				}

				u = r

			case <-keepalive_timer.C:
				if status.State == ESTABLISHED {
					conn.write(keepaliveMessage())
				}

			case <-hold_timer.C:
				conn.write(notificationMessage(HOLD_TIMER_EXPIRED, 0))
				status.LastError = "Hold timer expired"
				return
			}
		}
	}()

	return updates, done
}
