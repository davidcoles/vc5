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
	"bufio"
	"fmt"
	"net"
	"time"
)

// dig chaos txt version.bind @80.80.80.80

func zdnsquery(addr string, port uint16) bool {

	if port == 0 {
		return false
	}

	QUERY := []byte{
		0x00, 0x00, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x76, 0x65, 0x72,
		0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00,
		0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x56, 0x16, 0xf6,
		0x23, 0xc3, 0xf6, 0x35, 0x9c,
	}

	d := net.Dialer{Timeout: 1 * time.Second}
	conn, err := d.Dial("udp", fmt.Sprint("%s:%d", addr, port))

	if err != nil {
		return false
	}

	defer conn.Close()

	var buff [2948]byte

	var tid uint16 = uint16(time.Now().Unix() % 65536)

	QUERY[0] = byte(tid >> 8)
	QUERY[1] = byte(tid & 0xff)

	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))

	n, err := conn.Write(QUERY)

	if err != nil || n != len(QUERY) {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	n, err = bufio.NewReader(conn).Read(buff[:])

	if err != nil || n < 2 {
		return false
	}

	if tid != (uint16(buff[0])<<8 + uint16(buff[1])) {
		return false
	}

	return true
}
