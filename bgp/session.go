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
	"sync"
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
	//AdjRIBOut         []string
	Prefixes    int
	Attempts    uint64
	Connections uint64
	Established uint64
	LastError   string
	HoldTime    uint16
	LocalASN    uint16
	RemoteASN   uint16
}

type Session struct {
	c      chan Update
	p      Parameters
	r      []IP
	status Status
	mutex  sync.Mutex
	update Update
}

func NewSession(id IP, peer string, p Parameters, r []IP) *Session {
	s := &Session{p: p, r: r, status: Status{State: IDLE}, update: Update{RIB: r, Parameters: p}}
	s.c = s.session(id, peer)
	return s

}

func (s *Session) Status() Status {
	s.mutex.Lock()
	defer s.mutex.Unlock()
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

func (s *Session) state(state string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.status.State = state
}

func (s *Session) error(error string) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.status.LastError = error
	return error
}

func (s *Session) established(ht uint16, local, remote uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.status.State = ESTABLISHED
	s.status.Established++
	s.status.LastError = ""
	s.status.HoldTime = ht
	s.status.LocalASN = local
	s.status.RemoteASN = remote
}

func (s *Session) active() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.status.State = ACTIVE
	s.status.Attempts++
}
func (s *Session) connect() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.status.State = CONNECT
	s.status.Connections++
}

func (s *Session) update_stats(a, w uint64, d time.Duration, r []string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.status.Advertised += a
	s.status.Withdrawn += w
	s.status.UpdateCalculation = d / time.Millisecond
	//s.status.AdjRIBOut = r
	s.status.Prefixes = len(r)
}

func (s *Session) session(id IP, peer string) chan Update {

	updates := make(chan Update, 10)

	go func() {

		retry_time := 30 * time.Second

		timer := time.NewTimer(1) // fires immediately
		defer timer.Stop()

		var ok bool

		for {
			select {
			case <-timer.C:
				s.error(s.try(id, peer, updates))
				timer.Reset(retry_time)

			case s.update, ok = <-updates: // stores last update
				if !ok {
					return
				}
			}
		}

	}()

	return updates
}

func (s *Session) try(id IP, peer string, updates chan Update) string {

	as := s.update.Parameters.ASNumber
	ht := s.update.Parameters.HoldTime
	ip := s.update.Parameters.SourceIP
	src := s.update.Source()

	if ht < 3 {
		ht = 10
	}

	defer func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		s.status.State = IDLE
		//status.AdjRIBOut = nil
		s.status.Prefixes = 0
		s.status.Advertised = 0
		s.status.Withdrawn = 0
		s.status.HoldTime = 0
	}()

	s.active()

	conn, err := new_connection(src, peer)

	if err != nil {
		s.error(err.Error())
		return err.Error()
	}

	s.connect()

	defer conn.Close()

	conn.write(openMessage(as, ht, id))

	s.state(OPEN_SENT)

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
				return conn.Error
			}

			hold_timer.Reset(hold_time_ns)

			switch m.mtype {
			case M_NOTIFICATION:
				// note why
				return "NOTIFICATION" + m.notification.reason()

			case M_KEEPALIVE:
				if s.status.State == OPEN_SENT {
					conn.write(notificationMessage(FSM_ERROR, 0))
					return "OPEN_SENT, got KEEPALIVE - FSM error"
				}

			case M_OPEN:
				if s.status.State != OPEN_SENT {
					n := notificationMessage(FSM_ERROR, 0)
					conn.write(notificationMessage(FSM_ERROR, 0))
					return "OPEN" + n.notification.reason()
				}

				if m.open.version != 4 {
					n := notificationMessage(OPEN_ERROR, UNSUPPORTED_VERSION_NUMBER)
					conn.write(n)
					return "OPEN" + n.notification.reason()
				}

				if m.open.ht < 3 {
					n := notificationMessage(OPEN_ERROR, UNNACEPTABLE_HOLD_TIME)
					conn.write(n)
					return "OPEN" + n.notification.reason()
				}

				if m.open.id == id {
					n := notificationMessage(OPEN_ERROR, BAD_BGP_ID)
					conn.write(n)
					return "OPEN" + n.notification.reason()
				}

				if m.open.ht < ht {
					ht = m.open.ht
					hold_time_ns = time.Duration(ht) * time.Second
					keepalive_time_ns = hold_time_ns / 3
				}

				hold_timer.Reset(hold_time_ns)
				keepalive_timer.Reset(keepalive_time_ns)

				external = m.open.as != as

				s.established(ht, as, m.open.as)

				conn.write(keepaliveMessage())

				t := time.Now()
				aro, p := s.update.adjRIBOutP()
				conn.write(updateMessage(ip, as, p, external, advertise(aro)))
				s.update_stats(uint64(len(aro)), 0, time.Now().Sub(t), to_string(aro))

			case M_UPDATE:
				if s.status.State != ESTABLISHED {
					n := notificationMessage(FSM_ERROR, 0)
					conn.write(n)
					return s.status.State + "/UPDATE" + n.notification.reason()
				}
				// we just ignore updates!

			default:
				n := notificationMessage(MESSAGE_HEADER_ERROR, BAD_MESSAGE_TYPE)
				conn.write(n)
				return s.status.State + n.notification.reason()
			}

		case r, ok := <-updates:

			if !ok {
				//conn.write(notificationMessage(CEASE, ADMINISTRATIVE_SHUTDOWN))
				conn.write(shutdownMessage("That's all, folks!"))
				return "Local shutdown"
			}

			if s.status.State == ESTABLISHED {
				t := time.Now()
				a, w, nlris := r.updates(s.update)
				if len(nlris) != 0 {
					conn.write(updateMessage(ip, as, r.Parameters, external, nlris))
				}
				s.update_stats(a, w, time.Now().Sub(t), r.adjRIBOutString())
			}

			s.update = r

		case <-keepalive_timer.C:
			if s.status.State == ESTABLISHED {
				conn.write(keepaliveMessage())
			}

		case <-hold_timer.C:
			conn.write(notificationMessage(HOLD_TIMER_EXPIRED, 0))
			return "Hold timer expired"
		}
	}

}

/*
func (s *Session) _session(id IP, peer string, update Update) chan Update {

	updates := make(chan Update, 10)

	go func() {

		retry_time := 30 * time.Second

		timer := time.NewTimer(retry_time)
		timer.Stop()

		defer timer.Stop()

		connection, done := s.try(id, peer, update)

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
					default: // updates have backed up channel (unlikely, but possible)
						close(connection)
						connection = nil
						timer.Reset(retry_time)
						s.error("Technical difficulties")
					}
				}
			} else { // idle
				select {
				case update, ok = <-updates:
					if !ok {
						return
					}

				case <-timer.C:
					connection, done = s.try(id, peer, update)
				}
			}
		}
	}()

	return updates
}

func (s *Session) try(id IP, peer string, u Update) (chan Update, chan bool) {
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
			s.mutex.Lock()
			defer s.mutex.Unlock()
			s.status.State = IDLE
			//status.AdjRIBOut = nil
			s.status.Prefixes = 0
			s.status.Advertised = 0
			s.status.Withdrawn = 0
			s.status.HoldTime = 0
			close(done) // let upstream know that the connection has failed/closed
		}()

		s.active()

		conn, err := new_connection(u.Source(), peer)

		if err != nil {
			s.error(err.Error())
			return
		}

		s.connect()

		defer conn.Close()

		conn.write(openMessage(asn, ht, id))

		s.state(OPEN_SENT)

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
					s.error(conn.Error)
					return
				}

				hold_timer.Reset(hold_time_ns)

				switch m.mtype {
				case M_NOTIFICATION:
					// note why
					s.error("NOTIFICATION" + m.notification.reason())
					return

				case M_KEEPALIVE:
					if s.status.State == OPEN_SENT {
						conn.write(notificationMessage(FSM_ERROR, 0))
						return
					}

				case M_OPEN:
					if s.status.State != OPEN_SENT {
						n := notificationMessage(FSM_ERROR, 0)
						conn.write(notificationMessage(FSM_ERROR, 0))
						s.error("OPEN" + n.notification.reason())
						return
					}

					if m.open.version != 4 {
						n := notificationMessage(OPEN_ERROR, UNSUPPORTED_VERSION_NUMBER)
						conn.write(n)
						s.error("OPEN" + n.notification.reason())
						return
					}

					if m.open.ht < 3 {
						n := notificationMessage(OPEN_ERROR, UNNACEPTABLE_HOLD_TIME)
						conn.write(n)
						s.error("OPEN" + n.notification.reason())
						return
					}

					if m.open.id == id {
						n := notificationMessage(OPEN_ERROR, BAD_BGP_ID)
						conn.write(n)
						s.error("OPEN" + n.notification.reason())
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

					s.established(ht, asn, m.open.as)

					conn.write(keepaliveMessage())

					t := time.Now()
					aro := u.adjRIBOut()
					conn.write(updateMessage(ip, asn, u.Parameters, external, advertise(aro)))
					s.update_stats(uint64(len(aro)), 0, time.Now().Sub(t), to_string(aro))

				case M_UPDATE:
					if s.status.State != ESTABLISHED {
						n := notificationMessage(FSM_ERROR, 0)
						conn.write(n)
						s.error(s.status.State + "/UPDATE" + n.notification.reason())
						return
					}
					// we just ignore updates!

				default:
					n := notificationMessage(MESSAGE_HEADER_ERROR, BAD_MESSAGE_TYPE)
					conn.write(n)
					s.error(s.status.State + n.notification.reason())
				}

			case r, ok := <-updates:

				if !ok {
					//conn.write(notificationMessage(CEASE, ADMINISTRATIVE_SHUTDOWN))
					conn.write(shutdownMessage("That's all, folks!"))
					s.error("Local shutdown")
					return
				}

				if s.status.State == ESTABLISHED {
					t := time.Now()
					a, w, nlris := r.updates(u)
					if len(nlris) != 0 {
						conn.write(updateMessage(ip, asn, r.Parameters, external, nlris))
					}
					s.update_stats(a, w, time.Now().Sub(t), r.adjRIBOutString())
				}

				u = r

			case <-keepalive_timer.C:
				if s.status.State == ESTABLISHED {
					conn.write(keepaliveMessage())
				}

			case <-hold_timer.C:
				conn.write(notificationMessage(HOLD_TIMER_EXPIRED, 0))
				s.error("Hold timer expired")
				return
			}
		}
	}()

	return updates, done
}

*/
