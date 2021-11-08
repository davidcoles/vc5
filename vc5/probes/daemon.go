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

package probes

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
	//"strings"
)

type check struct {
	Type string
	Args []string
}

type result struct {
	Success bool
}

const PATH = "/run/vc5.sock"

func HTTPCheck(ip IP4, port uint16, path string, expect int) bool {
	return _HTTPCheck("http", ip, port, path, expect)
}

func HTTPSCheck(ip IP4, port uint16, path string, expect int) bool {
	return _HTTPCheck("https", ip, port, path, expect)
}

func _HTTPCheck(scheme string, ip IP4, port uint16, path string, expect int) bool {
	a := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	p := fmt.Sprintf("%d", port)
	r := fmt.Sprintf("%d", expect)
	c := &check{Type: scheme, Args: []string{a, p, path, r}}
	return check_client(c)
}

func TCPCheck(ip IP4, port uint16) bool {
	a := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	p := fmt.Sprintf("%d", port)
	c := &check{Type: "tcp", Args: []string{a, p}}
	return check_client(c)
}

var client *http.Client

func check_client(c *check) bool {
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", PATH)
				},
			},
		}
	}

	client.CloseIdleConnections()

	buff := new(bytes.Buffer)
	json.NewEncoder(buff).Encode(c)
	response, err := client.Post("http://unix/check/", "application/octet-stream", buff)

	if err != nil {
		return false
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false
	}

	body, err := ioutil.ReadAll(response.Body)

	var s result

	json.Unmarshal(body, &s)

	//fmt.Println(c, s)

	return s.Success
}

func Serve(netns string) {
	for {
		exec.Command("ip", "netns", "exec", netns, os.Args[0], PATH).Output()
		time.Sleep(1 * time.Second)
	}
}

func Daemon(path string) {

	os.Remove(path)

	http.HandleFunc("/check/", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)

		defer r.Body.Close()

		if err != nil {
			return
		}

		var c check

		json.Unmarshal(body, &c)

		fmt.Println("got:", c)

		var ok bool

		switch c.Type {
		case "http":
			ok = httpget(c.Type, c.Args[0], c.Args[1], c.Args[2], c.Args[3])
		case "https":
			ok = httpget(c.Type, c.Args[0], c.Args[1], c.Args[2], c.Args[3])
		case "tcp":
			ok = tcpdial(c.Args[0], c.Args[1])
		}

		w.WriteHeader(http.StatusOK)

		j, _ := json.Marshal(&result{Success: ok})

		w.Write(j)

		return
	})

	s, err := net.Listen("unix", PATH)

	if err != nil {
		panic(err)
	}

	server := http.Server{}

	server.Serve(s)
}

func tcpdial(addr string, port string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("tcp", addr+":"+port)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func httpget(scheme string, address string, port string, url string, expect string) bool {

	if client == nil {
		transport := &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 2 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 1 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		}

		client = &http.Client{
			Timeout:   time.Second * 3,
			Transport: transport,
		}
	}

	client.CloseIdleConnections()

	uri := fmt.Sprintf("%s://%s:%s/%s", scheme, address, port, url)

	resp, err := client.Get(uri)

	if err != nil {
		return false
	}

	defer resp.Body.Close()

	sc := fmt.Sprintf("%d", resp.StatusCode)

	if sc != expect {
		return false
	}

	return true
}