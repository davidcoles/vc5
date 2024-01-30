package kernel

import (
	"net"
	"time"
)

type ICMPs struct {
	submit chan string
}

func ICMP() *ICMPs {

	var icmp ICMPs

	c, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		//log.Fatalf("listen err, %s", err)
		return nil
	}

	icmp.submit = make(chan string, 1000)
	go icmp.probe(c)

	return &icmp
}

func (s *ICMPs) Ping(target string) {
	select {
	case s.submit <- target:
	default:
	}
}

func (s *ICMPs) Close() {
	close(s.submit)
}

func (s *ICMPs) echoRequest() []byte {

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

func (s *ICMPs) probe(socket net.PacketConn) {

	defer socket.Close()

	for target := range s.submit {
		go func() {
			socket.SetWriteDeadline(time.Now().Add(1 * time.Second))
			socket.WriteTo(s.echoRequest(), &net.IPAddr{IP: net.ParseIP(target)})
		}()
	}
}
