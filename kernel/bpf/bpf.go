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

package bpf

//#include "bpf.h"
import "C"

type Features struct {
	SKIP_STATS bool
	SKIP_STATE bool
	SKIP_CONNS bool
	SKIP_QUEUE bool
	BLOCKLIST  bool
	MULTINIC   bool
}

func (f Features) Render() uint8 {
	var r uint8
	if f.SKIP_STATE {
		r |= C.F_SKIP_STATE
	}
	if f.SKIP_STATS {
		r |= C.F_SKIP_STATS
	}
	if f.SKIP_CONNS {
		r |= C.F_SKIP_CONNS
	}
	if f.SKIP_QUEUE {
		r |= C.F_SKIP_QUEUE
	}
	if f.BLOCKLIST {
		r |= C.F_BLOCKLIST
	}
	if f.MULTINIC {
		r |= C.F_MULTINIC
	}
	return r
}
