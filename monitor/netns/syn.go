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

package netns

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type SynChecks = SYN

type synkey struct {
	seq  uint32
	rem  [4]byte
	locp uint16
	remp uint16
}

type SYN struct {
	src [4]byte
	con net.PacketConn
	syn sync.Map
	seq atomic.Uint32
}

func (s *SYN) Probe(addr string, port uint16) bool {

	ip := net.ParseIP(addr).To4()

	if ip == nil || len(ip) != 4 {
		return false
	}

	ok, _ := s.Check([4]byte{ip[0], ip[1], ip[2], ip[3]}, port)

	return ok
}

func SynServer(addr string, rst bool) *SYN {
	return syn(addr, rst)
}

func Syn(addr string) *SYN {
	return syn(addr, true)
}

func syn(addr string, rst bool) *SYN {

	ip := net.ParseIP(addr).To4()

	if ip == nil || len(ip) != 4 {
		return nil
	}

	src := [4]byte{ip[0], ip[1], ip[2], ip[3]}

	con, err := net.ListenPacket("ip4:tcp", addr)

	if err != nil {
		log.Fatalf("listen err, %s", err)
		return nil
	}

	f := &SYN{
		con: con,
		src: src,
	}

	go f.background(rst)

	return f
}

func (s *SYN) Check(dst [4]byte, remp uint16) (bool, string) {

	socket := s.con
	src := s.src

	seq := s.seq.Add(1)
	locp := uint16(seq%4999) + 61000

	k := synkey{seq: seq + 1, rem: dst, locp: locp, remp: remp} // reply will include ack seq+1
	c := make(chan bool)                                        // closed when reply received

	packet := synrst(src, dst, locp, remp, seq, false)

	addr := net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", dst[0], dst[1], dst[2], dst[3]))

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

	socket.SetWriteDeadline(time.Now().Add(1 * time.Second))

	s.syn.Store(k, c)

	_, err := socket.WriteTo(packet, &net.IPAddr{IP: addr})

	if err != nil {
		return false, err.Error()
	}

	select {
	case <-c:
		s.syn.Delete(k)
		return true, ""
	case <-timer.C:
	}

	return false, "Timeout"
}

func (s *SYN) background(reset bool) {

	var buf [1500]byte

	for {
		s.con.SetReadDeadline(time.Now().Add(2 * time.Second))

		n, peer, err := s.con.ReadFrom(buf[:])

		if err != nil || n < 20 {
			continue
		}

		flg := buf[13]
		//cwr := (flg & 128) != 0
		//ece := (flg & 64) != 0
		//urg := (flg & 32) != 0
		ack := (flg & 16) != 0
		//psh := (flg & 8) != 0
		rst := (flg & 4) != 0
		syn := (flg & 2) != 0
		fin := (flg & 1) != 0

		if !syn || !ack || fin || rst {
			continue
		}

		addr := net.ParseIP(peer.String()).To4()

		if addr == nil || len(addr) != 4 {
			continue
		}

		rem := [4]byte{addr[0], addr[1], addr[2], addr[3]}

		remp := uint16(buf[0])<<8 | uint16(buf[1])
		locp := uint16(buf[2])<<8 | uint16(buf[3])
		acn := uint32(buf[8])<<24 | uint32(buf[9])<<16 | uint32(buf[10])<<8 | uint32(buf[11])

		v, ok := s.syn.LoadAndDelete(synkey{seq: acn, rem: rem, locp: locp, remp: remp})

		if !ok {
			continue
		}

		val, ok := v.(chan bool)

		if !ok {
			continue
		}

		//if syn && ack && !fin && !rst {

		close(val)

		if reset {

			go func() {
				packet := synrst(s.src, rem, locp, remp, acn, true)
				addr := net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", rem[0], rem[1], rem[2], rem[3]))

				s.con.SetWriteDeadline(time.Now().Add(1 * time.Second))
				s.con.WriteTo(packet, &net.IPAddr{IP: addr})
			}()
		}
	}
}

func synrst(src, dst [4]byte, srcPort, dstPort uint16, seq uint32, reset bool) []byte {

	var sum uint32
	var buf [20]byte

	buf[0] = byte(srcPort >> 8)
	buf[1] = byte(srcPort)
	buf[2] = byte(dstPort >> 8)
	buf[3] = byte(dstPort)
	buf[12] = 5 << 4 // header length 5 * 32bit-words - top 4 bits

	if reset {
		buf[13] = 4 // RST flag
	} else {
		buf[13] = 2 // SYN flag
	}

	buf[4] = byte(seq >> 24)
	buf[5] = byte(seq >> 16)
	buf[6] = byte(seq >> 8)
	buf[7] = byte(seq)

	if !reset {
		win := 64240 // window size
		buf[14] = byte(win >> 8)
		buf[15] = byte(win)
	}

	// pseudo-header
	sum += uint32(uint16(src[0])<<8 | uint16(src[1]))
	sum += uint32(uint16(src[2])<<8 | uint16(src[3]))
	sum += uint32(uint16(dst[0])<<8 | uint16(dst[1]))
	sum += uint32(uint16(dst[2])<<8 | uint16(dst[3]))
	sum += uint32(uint16(6)) // TCP protocol number
	sum += uint32(len(buf))

	for n := 0; n < len(buf); n += 2 {
		sum += uint32(uint16(buf[n])<<8 | uint16(buf[n+1]))
	}

	var cs uint16

	cs = uint16(sum>>16) + uint16(sum&0xffff)
	cs = ^cs

	buf[16] = byte(cs >> 8)
	buf[17] = byte(cs & 0xff)

	return buf[:]
}
