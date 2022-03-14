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

package manage

import (
	"bufio"
	//"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"time"

	"github.com/davidcoles/vc5/config"
)

func read_macs(r map[IP4]config.Info) (map[IP4]MAC, error) {

	rip := make(map[IP4]bool)

	for k, _ := range r {
		rip[k] = true
	}

	ip2mac := make(map[IP4]MAC)
	ip2nic := make(map[IP4]*net.Interface)

	re := regexp.MustCompile(`^(\S+)\s+0x1\s+0x.\s+(\S+)\s+\S+\s+(\S+)$`)

	file, err := os.OpenFile("/proc/net/arp", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()

		m := re.FindStringSubmatch(line)

		if len(m) > 3 {
			//fmt.Println(m[1], m[2], m[3])

			ip := net.ParseIP(m[1])

			if ip == nil {
				continue
			}

			ip = ip.To4()

			if ip == nil || len(ip) != 4 {
				continue
			}

			hw, err := net.ParseMAC(m[2])

			if err != nil || len(hw) != 6 {
				continue
			}

			iface, err := net.InterfaceByName(m[3])

			if err != nil {
				continue
			}

			//fmt.Println(ip, hw, iface.Name, iface.Index)

			var ip4 IP4
			var mac [6]byte

			copy(ip4[:], ip[:])
			copy(mac[:], hw[:])

			if ip4.String() == "0.0.0.0" {
				continue
			}

			if mac == [6]byte{0, 0, 0, 0, 0, 0} {
				continue
			}

			if _, ok := rip[ip4]; !ok {
				continue
			}

			ip2mac[ip4] = mac
			ip2nic[ip4] = iface
		}
	}

	return ip2mac, nil
}

func arp(reals map[IP4]config.Info) chan map[IP4]config.Info {

	c := make(chan map[IP4]config.Info, 100)
	c <- reals

	go func() {

		icmp := ICMP()

		state := make(map[IP4]MAC)

		ticker := time.NewTicker(10 * time.Second)

		defer func() {
			icmp.Stop()
			ticker.Stop()
			// could clean up XDP, but data structures will
			// be deleted from kernel anyway - so no point
		}()

		for {
			var ok bool
			select {
			case <-ticker.C:
			case reals, ok = <-c:
				if !ok {
					return
				}
			}

			for k, _ := range reals {
				icmp.Ping(k.String())
			}

			time.Sleep(1 * time.Second)

			arp, err := read_macs(reals)

			if err != nil {
				continue
			}

			macs_to_delete := make(map[MAC]bool)
			for _, v := range state {
				macs_to_delete[v] = true
			}

			for rip, real := range reals {

				if mac, ok := state[rip]; ok {

					new_mac := arp[rip] // might be 00:00:00:00:00:00 - that's OK
					if new_mac != mac { // update state if changed
						state[rip] = new_mac
						ctrl.SetRipMac(rip, new_mac)
						ctrl.SetBackendRec(rip, new_mac, real.VLAN, real.Index, 0)
					}
					delete(macs_to_delete, new_mac)

				} else {

					new_mac := arp[rip] // might be 00:00:00:00:00:00 - that's OK
					state[rip] = new_mac
					ctrl.SetRipMac(rip, new_mac)
					ctrl.SetBackendRec(rip, new_mac, real.VLAN, real.Index, 0)
					delete(macs_to_delete, new_mac)

				}
			}

			for rip, _ := range state {
				if _, ok := reals[rip]; !ok {
					delete(state, rip)
					ctrl.DelRip(rip)
				}
			}

			for mac, _ := range macs_to_delete {
				ctrl.DelMac(mac)
			}

		}

	}()
	return c
}

func craftICMP() []byte {

	var csum uint32
	wb := make([]byte, 8)

	wb[0] = 8
	wb[1] = 0

	for n := 0; n < 8; n += 2 {
		csum += uint32(uint16(wb[n])<<8 | uint16(wb[n+1]))
	}

	var cs uint16

	cs = uint16(csum>>16) + uint16(csum&0xffff)
	cs = ^cs

	wb[2] = byte(cs >> 8)
	wb[3] = byte(cs & 0xff)

	return wb
}

type ICMPs struct {
	submit chan string
}

//func ICMP(source string) *ICMPs {
func ICMP() *ICMPs {

	var icmp ICMPs

	c, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		log.Fatalf("listen err, %s", err)
	}

	icmp.submit = make(chan string, 1000)
	go icmp.probe(c)

	return &icmp
}

func (s *ICMPs) probe(socket net.PacketConn) {

	defer socket.Close()

	for target := range s.submit {

		wb := craftICMP()

		socket.SetWriteDeadline(time.Now().Add(1 * time.Second))

		if _, err := socket.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(target)}); err != nil {
			log.Fatalf("WriteTo err, %s", err)
		}
	}
}

func (s *ICMPs) Stop() {
	close(s.submit)
}

func (s *ICMPs) Ping(target string) {
	select {
	case s.submit <- target:
	default:
	}
}
