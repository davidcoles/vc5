package bgp4

import (
	//"fmt"
	"net"
)

type IP = [4]byte

type Update struct {
	RIB        []IP
	Parameters *Parameters
}

func (r *Update) adjRIBOut() []IP4 {
	return r.Parameters.Filter(r.RIB)
}

func (r *Update) Filter() []IP4 {
	return r.Parameters.Filter(r.RIB)
}

func (p *Parameters) Filter(dest []IP) []IP4 {
	var pass []IP4

filter:
	for _, i := range dest {
		ip4 := IP4(i)

		ip := net.ParseIP(ip4.String())

		if ip == nil {
			continue
		}

		for _, ipnet := range p.Accept {
			n := net.IPNet(ipnet)
			if n.Contains(ip) {
				pass = append(pass, i)
				continue filter
			}
		}

		for _, ipnet := range p.Reject {
			n := net.IPNet(ipnet)
			if n.Contains(ip) {
				continue filter
			}
		}

		pass = append(pass, i)
	}

	return pass
}

func Filter(dest []IP4, filter []IP4) []IP4 {

	reject := map[IP4]bool{}

	if len(filter) == 0 {
		return dest
	}

	for _, i := range filter {
		reject[i] = true
	}

	var o []IP4

	for _, i := range dest {
		if _, rejected := reject[i]; !rejected {
			o = append(o, i)
		}
	}

	return o
}

func (r *Update) full() []nlri {
	var n []nlri
	//for _, ip := range r.RIB {
	for _, ip := range r.adjRIBOut() {
		n = append(n, nlri{ip: ip, up: true})
	}

	return n
}

func (r Update) Copy() Update {
	var rib []IP

	for _, x := range r.RIB {
		rib = append(rib, x)
	}

	return Update{RIB: rib, Parameters: r.Parameters}
}

// func (r *Update) updates(o *Update) (bool, []nlri) {
func (c *Update) updates(p Update) []nlri {
	var n []nlri

	var vary bool = c.Parameters.Diff(p.Parameters)

	curr := map[IP4]bool{}
	prev := map[IP4]bool{}

	for _, ip := range c.adjRIBOut() {
		curr[ip] = true
	}

	for _, ip := range p.adjRIBOut() {
		prev[ip] = true
	}

	for ip, _ := range curr {
		_, ok := prev[ip] // if didn't exist in previous rib, or params have changed then need to advertise
		if !ok || vary {
			n = append(n, nlri{ip: ip, up: true})
		}
	}

	for ip, _ := range prev {
		_, ok := curr[ip] // if not in current rib then need to withdraw
		if !ok {
			n = append(n, nlri{ip: ip, up: false})
		}
	}

	return n
}

func (c *Update) updates2(p Update) map[IP]bool {
	n := map[IP]bool{}

	var vary bool = c.Parameters.Diff(p.Parameters)

	curr := map[IP4]bool{}
	prev := map[IP4]bool{}

	for _, ip := range c.adjRIBOut() {
		curr[ip] = true
	}

	for _, ip := range p.adjRIBOut() {
		prev[ip] = true
	}

	for ip, _ := range curr {
		_, ok := prev[ip] // if didn't exist in previous rib, or params have changed then need to advertise
		if !ok || vary {
			//n = append(n, nlri{ip: ip, up: true})
			n[ip] = true
		}
	}

	for ip, _ := range prev {
		_, ok := curr[ip] // if not in current rib then need to withdraw
		if !ok {
			//n = append(n, nlri{ip: ip, up: false})
			n[ip] = false
		}
	}

	return n
}

func RIBSDiffer(a, b []IP) bool {

	x := map[IP]bool{}
	for _, i := range a {
		x[i] = true
	}

	y := map[IP]bool{}
	for _, i := range b {
		y[i] = true
	}

	if len(y) != len(y) {
		return true
	}

	for i, _ := range x {
		_, ok := y[i]
		if !ok {
			return true
		}
		delete(y, i)
	}

	return len(y) != 0
}
