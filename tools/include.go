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

package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	p := os.Args[1]
	fmt.Print("package bpf\n\nvar " + p + " = []byte{")

	n := os.Args[2]
	f, _ := os.Open(n)

	buff := make([]byte, 8192)

	for {
		n, _ := io.ReadFull(f, buff)
		for x, b := range buff {
			if x < n {
				fmt.Printf("0x%02x, ", b)
			}
		}
		if n != len(buff) {
			//fmt.Println(e)
			break
		}
	}
	fmt.Println("}")
}
