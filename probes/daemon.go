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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/davidcoles/vc5/logger"
	"github.com/davidcoles/vc5/types"
)

type IP4 = types.IP4

type check struct {
	Type string
	Args []string
}

type result struct {
	Success bool
	Message string
}

const PATH = "/run/vc5.sock"

func ptoa(p uint16) string {
	return fmt.Sprintf("%d", p)
}
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}

func HTTPCheck(ip IP4, port uint16, path string, expect int, host string) (bool, string) {
	return _HTTPCheck("http", ip, port, path, expect, host)
}

func HTTPSCheck(ip IP4, port uint16, path string, expect int, host string) (bool, string) {
	return _HTTPCheck("https", ip, port, path, expect, host)
}

func _HTTPCheck(scheme string, ip IP4, port uint16, path string, expect int, host string) (bool, string) {
	return check_client(&check{Type: scheme, Args: []string{ip.String(), ptoa(port), path, itoa(expect), host}})
}

func TCPCheck(ip IP4, port uint16) (bool, string) {
	return check_client(&check{Type: "tcp", Args: []string{ip.String(), ptoa(port)}})
}

func SYNCheck(ip IP4, port uint16) (bool, string) {
	return check_client(&check{Type: "syn", Args: []string{ip.String(), ptoa(port)}})
}

var client *http.Client

func check_client(c *check) (bool, string) {
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", PATH)
				},
			},
		}
	}

	defer client.CloseIdleConnections()

	buff := new(bytes.Buffer)
	json.NewEncoder(buff).Encode(c)
	response, err := client.Post("http://unix/check/", "application/octet-stream", buff)

	if err != nil {
		return false, "AF_UNIX: " + err.Error()
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Sprintf("AF_UNIX: %d", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)

	var s result

	json.Unmarshal(body, &s)

	//fmt.Println(c, s)

	return s.Success, s.Message
}

func Serve(netns string, logs *logger.Logger) {
	for {
		//exec.Command("ip", "netns", "exec", netns, os.Args[0], PATH).Output()
		//exec.Command("/bin/sh", "-c", "ip netns exec vc5 "+os.Args[0]+" "+PATH+" >/tmp/vc5.log 2>&1").Output()
		//cmd := exec.Command("/bin/sh", "-c", "ip netns exec vc5 "+os.Args[0]+" "+PATH+" >/tmp/vc5.log 2>&1")
		//cmd := exec.Command("/bin/sh", "-c", "ip netns exec vc5 "+os.Args[0]+" "+PATH+" 2>&1")
		cmd := exec.Command("ip", "netns", "exec", netns, os.Args[0], PATH)

		_, _ = cmd.StdinPipe()
		stderr, _ := cmd.StderrPipe()
		stdout, _ := cmd.StdoutPipe()

		reader := func(s string, fh io.ReadCloser) {
			scanner := bufio.NewScanner(fh)
			for scanner.Scan() {
				logs.DEBUG("Daemon", s, scanner.Text())
			}
		}

		go reader("stderr", stderr)

		if err := cmd.Start(); err != nil {
			logs.DEBUG("Daemon:", err)
		} else {
			reader("stdout", stdout)

			if err := cmd.Wait(); err != nil {
				logs.DEBUG("Daemon:", err)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func Daemon(path, ipaddr string) {

	go func() {
		reader := bufio.NewReader(os.Stdin)
		c, _, err := reader.ReadRune()

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(c)
	}()

	os.Remove(path)

	syn := Syn(ipaddr)

	http.HandleFunc("/check/", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)

		defer r.Body.Close()

		if err != nil {
			return
		}

		var c check

		json.Unmarshal(body, &c)

		//fmt.Println("got:", c)

		var ok bool
		var msg string

		switch c.Type {
		case "http":
			ok, msg = httpget(c.Type, c.Args[0], c.Args[1], c.Args[2], c.Args[3], c.Args[4])
		case "https":
			ok, msg = httpget(c.Type, c.Args[0], c.Args[1], c.Args[2], c.Args[3], c.Args[4])
		case "tcp":
			ok = tcpdial(c.Args[0], c.Args[1])
		case "syn":
			ok = syn.ProbeS(c.Args[0], c.Args[1])
		}

		w.WriteHeader(http.StatusOK)

		j, _ := json.Marshal(&result{Success: ok, Message: msg})

		w.Write(j)

		return
	})

	s, err := net.Listen("unix", PATH)

	if err != nil {
		log.Fatal(err)
	}

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func tcpdial(addr string, port string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", addr+":"+port)
	if err != nil {
		return false
	}
	one := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	//c.SetReadDeadline(time.Now())
	n, err := c.Read(one)
	c.Close()

	//log.Println(n, err)

	if err == nil && n != 0 {
		return true
	}

	if err == io.EOF {
		return false
	}

	switch err := err.(type) {
	case net.Error:
		if err.Timeout() {
			//log.Println("This was a net.Error with a Timeout")
			return true
		}
	}

	return false
}

func httpget(scheme string, address string, port string, path string, expect string, hostname string) (bool, string) {

	if client == nil {

		transport := &http.Transport{
			//DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			//	return net.Dial("tcp", address+":"+port)
			//},
			Dial: (&net.Dialer{
				Timeout: 2 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 1 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		}

		client = &http.Client{
			Timeout:   time.Second * 3,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	defer client.CloseIdleConnections()

	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	url := fmt.Sprintf("%s://%s:%s/%s", scheme, address, port, path)
	req, err := http.NewRequest("GET", url, nil)
	if hostname != "" {
		req.Host = hostname
	}
	resp, err := client.Do(req)

	if err != nil {
		//fmt.Println("get: ", hostname, uri, err)
		return false, fmt.Sprintf("GET: %s:%s %s %v", address, port, url, resp)
	}

	//body, err := ioutil.ReadAll(r.Body)

	defer resp.Body.Close()

	sc := fmt.Sprintf("%d", resp.StatusCode)

	if sc != expect {
		return false, fmt.Sprintf("%s: %s:%s %s %v", sc, address, port, url, resp)
	}

	return true, ""
}
