package bgp4

import (
	"github.com/davidcoles/vc5/types"
)

type Config struct {
	RIB   []IP
	Peers map[IP4]Parameters
}

type Pool2 struct {
	c chan Config
}

func (p *Pool2) Update(c Config) {
	p.c <- c
}

func (p *Pool2) Close() {
	close(p.c)
}

func NewPool(addr string, c Config) *Pool2 {

	var nul IP4

	id, ok := types.ParseIP(addr)

	if !ok || id == nul {
		return nil
	}

	ip := id

	p := &Pool2{c: make(chan Config)}

	go func() {

		m := map[IP4]chan Update{}

		defer func() {
			for _, v := range m {
				close(v)
			}
		}()

		for i := range p.c {

			for peer, v := range i.Peers {

				if v.SourceIP == nul {
					v.SourceIP = ip
				}

				u := Update{RIB: i.RIB, Parameters: v}

				if d, ok := m[peer]; ok {
					select {
					case d <- u:
					default: // stopped responding - start a new instance
						close(d)
						m[peer] = session(id, peer, u)
					}
				} else {
					m[peer] = session(id, peer, u)
				}
			}

			for peer, v := range m {
				if _, ok := i.Peers[peer]; !ok {
					close(v)
					delete(m, peer)
				}
			}
		}

	}()

	p.c <- c

	return p
}
