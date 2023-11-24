package bgp4

import (
	"fmt"
	"github.com/davidcoles/vc5/types"
)

type Pool struct {
	c chan map[IP4]Parameters
	r chan []IP
}

func (p *Pool) Configure(c map[IP4]Parameters) {
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

func NewPool(addr string, peers map[IP4]Parameters, rib_ []IP) *Pool {

	rib := dup(rib_)

	var nul IP4

	id, ok := types.ParseIP(addr)

	if !ok || id == nul {
		return nil
	}

	ip := id

	p := &Pool{c: make(chan map[IP4]Parameters), r: make(chan []IP)}

	go func() {

		m := map[IP4]chan Update{}

		defer func() {
			for _, v := range m {
				close(v)
			}
		}()

		for {
			select {
			case r := <-p.r:

				rib = dup(r)

				for _, v := range m {
					v <- Update{RIB: rib}
				}

			case i, ok := <-p.c:

				if !ok {
					return
				}

				for peer, x := range i {
					v := x

					fmt.Println(v)

					if v.SourceIP == nul {
						v.SourceIP = ip
					}

					u := Update{RIB: rib, Parameters: &v}

					if d, ok := m[peer]; ok {
						d <- u
					} else {
						m[peer] = session(id, peer, u)
					}
				}

				for peer, v := range m {
					if _, ok := i[peer]; !ok {
						close(v)
						delete(m, peer)
					}
				}
			}
		}
	}()

	p.c <- peers

	return p
}
