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

type status = map[string]Status

type Pool struct {
	c chan map[string]Parameters
	r chan []IP
	s chan chan status
}

func (p *Pool) Status() status {
	c := make(chan status)
	p.s <- c
	return <-c
}

func (p *Pool) Configure(c map[string]Parameters) {
	p.c <- c
}

func (p *Pool) RIB(r []IP) {
	p.r <- r
}

func (p *Pool) Close() {
	close(p.c)
}

func dup(i []IP) (o []IP) {
	for _, x := range i {
		o = append(o, x)
	}
	return
}

func NewPool(addr string, peers map[string]Parameters, rib_ []IP) *Pool {

	rib := dup(rib_)

	var nul IP

	id, ok := parseIP(addr)

	if !ok || id == nul {
		return nil
	}

	ip := id

	p := &Pool{c: make(chan map[string]Parameters), r: make(chan []IP), s: make(chan chan status)}

	go func() {

		m := map[string]*Session{}

		defer func() {
			for _, v := range m {
				v.Close()
			}
		}()

		for {
			select {
			case c := <-p.s:
				s := map[string]Status{}
				for peer, session := range m {
					s[peer] = session.Status()
				}
				c <- s

			case r := <-p.r:

				rib = dup(r)

				for _, v := range m {
					v.RIB(rib)
				}

			case i, ok := <-p.c:

				if !ok {
					return
				}

				for peer, params := range i {

					if params.SourceIP == nul {
						params.SourceIP = ip
					}

					if session, ok := m[peer]; ok {
						session.Configure(params)
					} else {
						m[peer] = NewSession(id, peer, params, rib)
					}
				}

				// if any sessions don't appear in the config map then close and remove them
				for peer, session := range m {
					if _, ok := i[peer]; !ok {
						session.Close()
						delete(m, peer)
					}
				}
			}
		}
	}()

	p.c <- peers

	return p
}
