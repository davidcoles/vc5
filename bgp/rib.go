package bgp4

import (
	"net"
)

type Update struct {
	RIB        []IP
	Parameters *Parameters
}

func (r *Update) adjRIBOut() []IP {
	return r.Parameters.Filter(r.RIB)
}

func (r *Update) Filter() []IP {
	return r.Parameters.Filter(r.RIB)
}

func (p *Parameters) Filter(dest []IP) []IP {
	var pass []IP

filter:
	for _, i := range dest {

		ip := net.ParseIP(ip_string(i))

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

func Filter(dest []IP, filter []IP) []IP {

	reject := map[IP]bool{}

	if len(filter) == 0 {
		return dest
	}

	for _, i := range filter {
		reject[i] = true
	}

	var o []IP

	for _, i := range dest {
		if _, rejected := reject[i]; !rejected {
			o = append(o, i)
		}
	}

	return o
}

func (r *Update) full() map[IP]bool {
	n := map[IP]bool{}
	for _, ip := range r.adjRIBOut() {
		n[ip] = true
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

func (c *Update) updates(p Update) map[IP]bool {
	n := map[IP]bool{}

	var vary bool = c.Parameters.Diff(p.Parameters)

	curr := map[IP]bool{}
	prev := map[IP]bool{}

	for _, ip := range c.adjRIBOut() {
		curr[ip] = true
	}

	for _, ip := range p.adjRIBOut() {
		prev[ip] = true
	}

	for ip, _ := range curr {
		_, ok := prev[ip] // if didn't exist in previous rib, or params have changed then need to advertise
		if !ok || vary {
			n[ip] = true
		}
	}

	for ip, _ := range prev {
		_, ok := curr[ip] // if not in current rib then need to withdraw
		if !ok {
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
