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
	"fmt"
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
	Prefixes          int
	Attempts          uint64
	Connections       uint64
	Established       uint64
	LastError         string
	HoldTime          uint16
	LocalASN          uint16
	RemoteASN         uint16
	EBGP              bool
	AdjRIBOut         []string
	LocalIP           string
}

const (
	CONNECTION_FAILED = iota
	REMOTE_SHUTDOWN
	LOCAL_SHUTDOWN
)

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
	s.status.EBGP = local != remote
}

func (s *Session) active(ht uint16, local uint16, ip [4]byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.status.State = ACTIVE
	s.status.Attempts++

	s.status.AdjRIBOut = nil
	s.status.Prefixes = 0
	s.status.Advertised = 0
	s.status.Withdrawn = 0
	s.status.HoldTime = ht
	s.status.LocalASN = local
	s.status.RemoteASN = 0
	s.status.EBGP = false
	s.status.LocalIP = ip_string(ip)
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
	s.status.AdjRIBOut = r
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
				b, n := s.try(id, peer, updates)
				var e string

				if b {
					e = fmt.Sprintf("Received notification[%d:%d]: %s", n.code, n.sub, note(n.code, n.sub))
					if len(n.data) > 0 {
						e += " (" + string(n.data) + ")"
					}
				} else {
					if n.code == 0 {
						e = note(n.code, n.sub)
					} else {
						e = fmt.Sprintf("Sent notification[%d:%d]: %s", n.code, n.sub, note(n.code, n.sub))
					}
					if len(n.data) > 0 {
						e += " (" + string(n.data) + ")"
					}
				}

				s.error(e)
				s.idle()
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

func (s *Session) idle() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.status.State = IDLE
}

func (s *Session) try(id IP, peer string, updates chan Update) (bool, notification) {

	asnumber := s.update.Parameters.ASNumber
	holdtime := s.update.Parameters.HoldTime
	sourceip := s.update.Parameters.SourceIP
	src := s.update.Source()
	var external bool

	if holdtime < 3 {
		holdtime = 10
	}

	s.active(holdtime, asnumber, sourceip)

	conn, err := new_connection(src, peer)

	if err != nil {
		return false, local(CONNECTION_FAILED, err.Error())
	}

	defer conn.Close()

	s.connect()

	conn.write(openMessage(asnumber, holdtime, id))

	s.state(OPEN_SENT)

	hold_time_ns := time.Duration(holdtime) * time.Second
	hold_timer := time.NewTimer(hold_time_ns)
	defer hold_timer.Stop()

	keepalive_time_ns := hold_time_ns / 3
	keepalive_timer := time.NewTicker(keepalive_time_ns)
	defer keepalive_timer.Stop()

	for {
		select {
		case m, ok := <-conn.C:

			if !ok {
				return false, local(REMOTE_SHUTDOWN, conn.Error)
			}

			hold_timer.Reset(hold_time_ns)

			switch m.mtype {
			case M_NOTIFICATION:
				return true, m.notification

			case M_KEEPALIVE:
				if s.status.State == OPEN_SENT {
					n := notificationMessage(FSM_ERROR, 0)
					conn.write(n)
					return false, n.notification
				}

			case M_OPEN:
				if s.status.State != OPEN_SENT {
					n := notificationMessage(FSM_ERROR, 0)
					conn.write(notificationMessage(FSM_ERROR, 0))
					return false, n.notification
				}

				if m.open.version != 4 {
					n := notificationMessage(OPEN_ERROR, UNSUPPORTED_VERSION_NUMBER)
					conn.write(n)
					return false, n.notification
				}

				if m.open.ht < 3 {
					n := notificationMessage(OPEN_ERROR, UNNACEPTABLE_HOLD_TIME)
					conn.write(n)
					return false, n.notification
				}

				if m.open.id == id {
					n := notificationMessage(OPEN_ERROR, BAD_BGP_ID)
					conn.write(n)
					return false, n.notification
				}

				if m.open.ht < holdtime {
					holdtime = m.open.ht
					hold_time_ns = time.Duration(holdtime) * time.Second
					keepalive_time_ns = hold_time_ns / 3
				}

				hold_timer.Reset(hold_time_ns)
				keepalive_timer.Reset(keepalive_time_ns)

				external = m.open.as != asnumber

				s.established(holdtime, asnumber, m.open.as)

				conn.write(keepaliveMessage())

				t := time.Now()
				aro, p := s.update.adjRIBOutP()
				conn.write(updateMessage(sourceip, asnumber, p, external, advertise(aro)))
				s.update_stats(uint64(len(aro)), 0, time.Now().Sub(t), to_string(aro))

			case M_UPDATE:
				if s.status.State != ESTABLISHED {
					n := notificationMessage(FSM_ERROR, 0)
					conn.write(n)
					return false, n.notification
				}
				// we just ignore updates!

			default:
				n := notificationMessage(MESSAGE_HEADER_ERROR, BAD_MESSAGE_TYPE)
				conn.write(n)
				return false, n.notification
			}

		case r, ok := <-updates:

			if !ok {
				//conn.write(notificationMessage(CEASE, ADMINISTRATIVE_SHUTDOWN))
				conn.write(shutdownMessage("That's all, folks!"))
				return false, local(LOCAL_SHUTDOWN, "")
			}

			if s.status.State == ESTABLISHED {
				t := time.Now()
				a, w, nlris := r.updates(s.update)
				if len(nlris) != 0 {
					conn.write(updateMessage(sourceip, asnumber, r.Parameters, external, nlris))
				}
				s.update_stats(a, w, time.Now().Sub(t), r.adjRIBOutString())
			}

			s.update = r

		case <-keepalive_timer.C:
			if s.status.State == ESTABLISHED {
				conn.write(keepaliveMessage())
			}

		case <-hold_timer.C:
			n := notificationMessage(HOLD_TIMER_EXPIRED, 0)
			conn.write(n)
			return false, n.notification
		}
	}

}

func local(s uint8, d string) notification {
	return notification{code: 0, sub: s, data: []byte(d)}
}
