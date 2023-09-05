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

package monitor

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type tuple struct {
	dest string
	locp uint16
	remp uint16
}

func (t *tuple) String() string {
	return fmt.Sprintf("%s:%d:%d", t.dest, t.locp, t.remp)
}

type synprobe struct {
	tuple tuple
	resp  chan bool
}

type SynChecks struct {
	probes sync.Map
	submit chan synprobe
	atomic uint64
}

func Syn(source string) *SynChecks {

	var syn SynChecks

	c, err := net.ListenPacket("ip4:tcp", source)
	if err != nil {
		log.Fatalf("listen err, %s", err)
	}
	//defer c.Close()

	syn.submit = make(chan synprobe, 100)
	go syn.sniffer(c)
	go syn.prober(c, source)

	return &syn
}

func (s *SynChecks) ProbeS(target, port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return s.Probe(target, uint16(p))
}

func (s *SynChecks) Probe(target string, port uint16) bool {

	x := atomic.AddUint64(&s.atomic, 1)

	var local uint16 = 65000 + uint16(x%500)

	t := tuple{dest: target, locp: local, remp: port}
	r := make(chan bool)

	s.submit <- synprobe{tuple: t, resp: r}

	select {
	case <-time.After(1 * time.Second):
	case <-r:
		return true
	}

	return false
}

func (s *SynChecks) prober(socket net.PacketConn, source string) {
	type qe struct {
		time  time.Time
		tuple tuple
	}

	for p := range s.submit {
		s.probes.Store(p.tuple.String(), p.resp)

		go func(k string) {
			time.Sleep(1 * time.Second)
			s.probes.Delete(k)
		}(p.tuple.String())

		target := p.tuple.dest

		wb := craftTCP(source, target, p.tuple.locp, p.tuple.remp)

		socket.SetWriteDeadline(time.Now().Add(1 * time.Second))

		if _, err := socket.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(target)}); err != nil {
			log.Fatalf("WriteTo err, %s", err)
		}

		var n int
		s.probes.Range(func(key, value interface{}) bool {
			n += 1
			return true
		})
		if n > 10 {
			fmt.Println(">>>", n)
		}
	}
}

func (s *SynChecks) sniffer(socket net.PacketConn) {

	for {
		socket.SetReadDeadline(time.Now().Add(2 * time.Second))

		rb := make([]byte, 1500)
		n, peer, err := socket.ReadFrom(rb)
		if err != nil || n < 20 {
			//log.Fatal(err)
			continue
		}

		f := rb[13]
		//cwr := (f & 128) != 0
		//ece := (f & 64) != 0
		//urg := (f & 32) != 0
		ack := (f & 16) != 0
		//psh := (f & 8) != 0
		rst := (f & 4) != 0
		syn := (f & 2) != 0
		fin := (f & 1) != 0

		remp := uint16(rb[0])<<8 | uint16(rb[1])
		locp := uint16(rb[2])<<8 | uint16(rb[3])

		t := tuple{dest: peer.String(), locp: locp, remp: remp}

		c, l := s.probes.LoadAndDelete(t.String())

		if l && syn && ack && !fin && !rst {
			close(c.(chan bool))
		}
	}
}

func craftTCP(sourceIP, targetIP string, sourcePort, targetPort uint16) []byte {

	var csum uint32
	wb := make([]byte, 20)

	wb[0] = byte(sourcePort >> 8)
	wb[1] = byte(sourcePort & 0xff)
	wb[2] = byte(targetPort >> 8)
	wb[3] = byte(targetPort & 0xff)
	wb[12] = 5 << 4 // header length 5 * 32bit-words - top 4 bits
	wb[13] = 2      // SYN flag

	wb[4] = 10 // seq. no
	wb[5] = 10
	wb[6] = 10
	wb[7] = 10

	wb[14] = 64240 >> 8   // window size
	wb[15] = 64240 & 0xff // window size

	src := net.ParseIP(sourceIP)[12:]
	dst := net.ParseIP(targetIP)[12:]
	len := uint16(20)

	// pseudo-header
	csum += uint32(uint16(src[0])<<8 | uint16(src[1]))
	csum += uint32(uint16(src[2])<<8 | uint16(src[3]))
	csum += uint32(uint16(dst[0])<<8 | uint16(dst[1]))
	csum += uint32(uint16(dst[2])<<8 | uint16(dst[3]))
	csum += uint32(uint16(6))
	csum += uint32(len)

	for n := 0; n < 20; n += 2 {
		csum += uint32(uint16(wb[n])<<8 | uint16(wb[n+1]))
	}

	var cs uint16

	cs = uint16(csum>>16) + uint16(csum&0xffff)
	cs = ^cs

	wb[16] = byte(cs >> 8)
	wb[17] = byte(cs & 0xff)

	return wb
}
