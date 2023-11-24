package bgp4

import (
	"net"
	"time"
)

func session(id, peer IP4, current Update) chan Update {

	updates := make(chan Update)

	go func() {
		ip := current.Parameters.SourceIP

		local := net.ParseIP(ip.String())

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

func active(id IP4, local net.IP, peer IP4, u Update) (chan Update, chan bool) {
	updates := make(chan Update)
	done := make(chan bool)

	go func() {

		ip := u.Parameters.SourceIP
		asn := u.Parameters.ASN
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

		conn.write(my_open(asn, ht, id))

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
						conn.write(my_notification(FSM_ERROR, 0))
						return
					}

				case M_OPEN:
					if state != OPEN_SENT {
						conn.write(my_notification(FSM_ERROR, 0))
						return
					}

					if m.open.version != 4 {
						conn.write(my_notification(OPEN_ERROR, UNSUPPORTED_VERSION_NUMBER))
						return
					}

					if m.open.ht < 3 {
						conn.write(my_notification(OPEN_ERROR, UNNACEPTABLE_HOLD_TIME))
						return
					}

					if m.open.id == id {
						conn.write(my_notification(OPEN_ERROR, BAD_BGP_ID))
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

					conn.write(my_keepalive())
					conn.write(my_update(ip, asn, u.Parameters, external, u.full2()))

				case M_UPDATE:
					if state != ESTABLISHED {
						conn.write(my_notification(FSM_ERROR, 0))
						return
					}
					// we just ignore updates!

				default:
					conn.write(my_notification(MESSAGE_HEADER_ERROR, BAD_MESSAGE_TYPE))
				}

			case r, ok := <-updates:

				if !ok {
					//conn.write(my_notification(CEASE, ADMINISTRATIVE_SHUTDOWN))
					conn.write(my_shutdown("That's all, folks!"))
					return
				}

				if r.Parameters == nil {
					r.Parameters = u.Parameters
				}

				if state == ESTABLISHED {

					nlris := r.updates(u)
					if len(nlris) != 0 {
						conn.write(my_update(ip, asn, r.Parameters, external, nlris))
					}
				}

				u = r

			case <-keepalive_timer.C:
				if state == ESTABLISHED {
					conn.write(my_keepalive())
				}

			case <-hold_timer.C:
				conn.write(my_notification(HOLD_TIMER_EXPIRED, 0))
				return
			}
		}
	}()

	return updates, done
}

func my_update(ip IP4, asn uint16, p *Parameters, external bool, m map[IP]bool) message {
	u := bgpupdate(p.SourceIP, p.ASN, external, p.LocalPref, p.MED, p.Communities, m)
	return message{mtype: M_UPDATE, body: u}
}

func my_open(asn uint16, ht uint16, id IP4) message {
	var m message
	var o open
	o.version = 4
	o.as = asn
	o.ht = ht
	o.id = id
	m.mtype = M_OPEN
	m.open = o
	return m
}

func my_keepalive() message {
	return message{mtype: M_KEEPALIVE}
}

func my_notification(code, sub uint8) message {
	return message{mtype: M_NOTIFICATION, notification: notification{code: code, sub: sub}}
}

func my_shutdown(d string) message {
	return message{mtype: M_NOTIFICATION, notification: notification{
		code: CEASE, sub: ADMINISTRATIVE_SHUTDOWN, data: []byte(d),
	}}
}
