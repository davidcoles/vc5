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

package kernel

import (
	"log"
	"net"
	"os/exec"
)

const NAMESPACE = "vc5"

var IP IP4 = IP4{10, 255, 255, 254}

type NetNS struct {
	IfA, IfB string
	IpA, IpB [4]byte
	HwA, HwB [6]byte
	Index    int
	NS       string
}

func (n *NetNS) Init() error {
	n.NS = NAMESPACE
	n.IfA = "vc5a"
	n.IfB = "vc5b"

	n.IpA = [4]byte{IP[0], IP[1], 255, 253}
	n.IpB = [4]byte{IP[0], IP[1], 255, 254}

	setup1(n.IfA, n.IfB)

	iface, err := net.InterfaceByName(n.IfA)
	if err != nil {
		return err
	}
	copy(n.HwA[:], iface.HardwareAddr[:])

	n.Index = iface.Index

	iface, err = net.InterfaceByName(n.IfB)
	if err != nil {
		return err
	}
	copy(n.HwB[:], iface.HardwareAddr[:])

	return nil
}

func (n *NetNS) Open() error {
	setup2(n.NS, n.IfA, n.IfB, n.IpA, n.IpB)
	return nil
}

func (n *NetNS) Close() { clean(n.IfA, n.NS) }

/**********************************************************************/

func clean(if1, ns string) {
	script1 := `
    ip link del ` + if1 + ` >/dev/null 2>&1 || true
    ip netns del ` + ns + ` >/dev/null 2>&1 || true
`
	exec.Command("/bin/sh", "-e", "-c", script1).Output()
}

func setup1(if1, if2 string) {
	script1 := `
ip link del ` + if1 + ` >/dev/null 2>&1 || true
ip link add ` + if1 + ` type veth peer name ` + if2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		log.Fatal(err)
	}
}

func setup2(ns, if1, if2 string, i1, i2 IP4) {
	ip1 := i1.String()
	ip2 := i2.String()
	cb := i1
	cb[2] = 0
	cb[3] = 0
	cbs := cb.String()

	script1 := `
ip netns del ` + ns + ` >/dev/null 2>&1 || true
ip l set ` + if1 + ` up
ip a add ` + ip1 + `/30 dev ` + if1 + `
ip netns add ` + ns + `
ip link set ` + if2 + ` netns ` + ns + `
ip netns exec vc5 /bin/sh -c "ip l set ` + if2 + ` up && ip a add ` + ip2 + `/30 dev ` + if2 + ` && ip r replace default via ` + ip1 + ` && ip netns exec ` + ns + ` ethtool -K ` + if2 + ` tx off"
ip r replace ` + cbs + `/16 via ` + ip2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		log.Fatal(err)
	}
}
