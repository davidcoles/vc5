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

package xdp

/*
#cgo LDFLAGS: -l:libbpf.a -lelf -lz
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "xdp.h"
*/
import "C"

import (
	"errors"
	"io/ioutil"
	//"time"
	//"net"
	"os"
	"unsafe"
)

const (
	BPF_ANY     = C.BPF_ANY
	BPF_NOEXIST = C.BPF_NOEXIST
	BPF_EXIST   = C.BPF_EXIST
)

type XDP struct {
	p unsafe.Pointer
}

func Simple(iface string, bindata []byte, program string) (*XDP, error) {
	tmpfile, err := ioutil.TempFile("/tmp", "balancer")

	if err != nil {
		return nil, err
	}

	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(bindata); err != nil {
		return nil, err
	}

	if err := tmpfile.Close(); err != nil {
		return nil, err
	}

	var xdp XDP

	o := C.load_bpf_file2(C.CString(tmpfile.Name()))
	C.xdp_link_detach2(C.CString(iface))
	C.load_bpf_section(o, C.CString(iface), C.CString(program), 1)

	xdp.p = o

	if xdp.p == nil {
		return nil, errors.New("Oops")
	}

	return &xdp, nil
}

func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}

func LoadBpfFile(veth string, bindata []byte, program string, native bool, peth ...string) (*XDP, error) {
	tmpfile, err := ioutil.TempFile("/tmp", "balancer")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(bindata); err != nil {
		return nil, err
	}

	if err := tmpfile.Close(); err != nil {
		return nil, err
	}

	var xdp XDP

	//xdp.p = C.load_bpf_file(C.CString(iface), C.CString(tmpfile.Name()), C.CString(program))
	o := C.load_bpf_file2(C.CString(tmpfile.Name()))

	for _, iface := range peth {
		C.xdp_link_detach2(C.CString(iface))
		if C.load_bpf_section(o, C.CString(iface), C.CString(program), C.int(boolint(native))) != 0 {
			return nil, errors.New("load_bpf_section() failed for " + iface)
		}
	}

	C.xdp_link_detach2(C.CString(veth))
	//C.load_bpf_section(o, C.CString(veth), C.CString(program), 0)
	//if C.load_bpf_section(o, C.CString(veth), C.CString(program), C.int(boolint(native))) != 0 {
	// don't use native mode - seems to break passing probes into a bridge
	if C.load_bpf_section(o, C.CString(veth), C.CString(program), C.int(0)) != 0 {
		return nil, errors.New("load_bpf_section() failed for " + veth)
	}
	xdp.p = o

	if xdp.p == nil {
		return nil, errors.New("Oops")
	}

	return &xdp, nil
}

func LoadBpfFile_(bindata []byte, p1, p2 string, native bool, bond, vetha, vethb string, eth ...string) (*XDP, error) {
	tmpfile, err := ioutil.TempFile("/tmp", "balancer")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(bindata); err != nil {
		return nil, err
	}

	if err := tmpfile.Close(); err != nil {
		return nil, err
	}

	var xdp XDP

	xdp.p = C.load_bpf_file2(C.CString(tmpfile.Name()))

	if xdp.p == nil {
		return nil, errors.New("Oops")
	}

	//if bond != "" {
	//	C.xdp_link_detach2(C.CString(bond))
	//	if C.load_bpf_section(xdp.p, C.CString(bond), C.CString("xdp_main2"), C.int(0)) != 0 {
	//		return nil, errors.New("load_bpf_section() failed for " + bond)
	//	}
	//}

	if vetha != "" {
		C.xdp_link_detach2(C.CString(vetha))
		if C.load_bpf_section(xdp.p, C.CString(vetha), C.CString(p2), C.int(0)) != 0 {
			return nil, errors.New("load_bpf_section() failed for " + vetha)
		}
	}

	/* weirdly, this seems to need to be set up in naive mode or probes don't succeed */
	if vethb != "" {
		C.xdp_link_detach2(C.CString(vethb))
		if C.load_bpf_section(xdp.p, C.CString(vethb), C.CString(p2), C.int(1)) != 0 {
			return nil, errors.New("load_bpf_section() failed for " + vethb)
		}
	}

	for _, iface := range eth {
		n := boolint(native)
		C.xdp_link_detach2(C.CString(iface))
		if C.load_bpf_section(xdp.p, C.CString(iface), C.CString(p1), C.int(n)) != 0 {
			return nil, errors.New("load_bpf_section() failed for " + iface)
		}
	}

	return &xdp, nil
}

func (x *XDP) CheckMap(i int, ks, vs int) bool {

	r := C.check_map_fd_info(C.int(i), C.int(ks), C.int(vs))

	if r != 0 {
		return false
	}

	return true
}

func (x *XDP) FindMap(m string, l ...int) int {
	r := C.bpf_object__find_map_by_name((*C.struct_bpf_object)(x.p), C.CString(m))
	if r == nil {
		return -1
	}
	return int(C.bpf_map__fd(r))
}

func BpfMapUpdateElem(i int, k, v unsafe.Pointer, flags uint64) int {
	return int(C.bpf_map_update_elem(C.int(i), k, v, C.ulonglong(flags)))
}

func BpfMapLookupAndDeleteElem(i int, k, v unsafe.Pointer) int {
	return int(C.bpf_map_lookup_and_delete_elem(C.int(i), k, v))
}

func BpfMapDeleteElem(i int, k unsafe.Pointer) int {
	return int(C.bpf_map_delete_elem(C.int(i), k))
}

func BpfMapLookupElem(i int, k, v unsafe.Pointer) int {
	return int(C.bpf_map_lookup_elem(C.int(i), k, v))
}

func BpfNumPossibleCpus() int {
	return int(C.libbpf_num_possible_cpus())
}

func XDPTest(bindata []byte, program string, native bool, nic string, p2, n2 string) (*XDP, error) {
	tmpfile, err := ioutil.TempFile("/tmp", "balancer")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(bindata); err != nil {
		return nil, err
	}

	if err := tmpfile.Close(); err != nil {
		return nil, err
	}

	var xdp XDP

	xdp.p = C.load_bpf_file2(C.CString(tmpfile.Name()))

	if xdp.p == nil {
		return nil, errors.New("Oops")
	}

	C.xdp_link_detach2(C.CString(nic))
	if C.load_bpf_section(xdp.p, C.CString(nic), C.CString(program), C.int(boolint(native))) != 0 {
		return nil, errors.New("load_bpf_section() failed for " + nic)
	}

	C.xdp_link_detach2(C.CString(n2))
	if C.load_bpf_section(xdp.p, C.CString(n2), C.CString(p2), C.int(boolint(native))) != 0 {
		return nil, errors.New("load_bpf_section() failed for " + n2)
	}

	return &xdp, nil
}
