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

	"github.com/davidcoles/vc5/types"
)

func Go(netns string, args ...string) {
	for {
		fmt.Println(args[0], args[1], args[2])

		cmd := exec.Command("ip", append([]string{"netns", "exec", netns}, args...)...)
		_, _ = cmd.StdinPipe()
		stderr, _ := cmd.StderrPipe()
		stdout, _ := cmd.StdoutPipe()

		reader := func(s string, fh io.ReadCloser) {
			scanner := bufio.NewScanner(fh)
			for scanner.Scan() {
				//logs.DEBUG("Daemon", s, scanner.Text())
				//log.Println("Daemon", s, scanner.Text())
			}
		}

		go reader("stderr", stderr)

		if err := cmd.Start(); err != nil {
			//logs.DEBUG("Daemon:", err)
			log.Println("Daemon", err)
		} else {
			reader("stdout", stdout)

			if err := cmd.Wait(); err != nil {
				//logs.DEBUG("Daemon:", err)
				log.Println("Daemon", err)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func Server(path string) {
	log.Println("RUNNING", path)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		c, _, err := reader.ReadRune()

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(c)
	}()

	os.Remove(path)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//defer r.Body.Close()

		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var foo Foo

		err = json.Unmarshal(body, &foo)

		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		fmt.Println(foo)

		var ok bool
		var st string

		switch foo.Scheme {
		case "http":
			ok, st = httpget(foo)
		case "https":
			ok, st = httpget(foo)
		default:
		}

		fmt.Println(">>>>", ok, st)

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})

	s, err := net.Listen("unix", path)

	if err != nil {
		log.Fatal(err)
	}

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

var client *http.Client

type Foo struct {
	IP     types.IP4
	Scheme string
	Check  types.Check
}

func Probe(path string, ip types.IP4, scheme string, check types.Check) bool {
	b, _ := Req(path, ip, scheme, check)
	return b
}
func Req(path string, ip types.IP4, scheme string, check types.Check) (bool, string) {

	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", path)
				},
			},
		}
	}

	defer client.CloseIdleConnections()

	foo := Foo{IP: ip, Scheme: scheme, Check: check}

	buff := new(bytes.Buffer)
	err := json.NewEncoder(buff).Encode(&foo)

	if err != nil {
		return false, "AF_UNIX: " + err.Error()
	}

	response, err := client.Post("http://unix/", "application/octet-stream", buff)

	if err != nil {
		return false, "AF_UNIX: " + err.Error()
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Sprintf("AF_UNIX: %d", response.StatusCode)
	}

	_, err = ioutil.ReadAll(response.Body)

	return true, ""
}

func httpget(foo Foo) (bool, string) {
	scheme := foo.Scheme
	address := foo.IP
	check := foo.Check

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
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	defer client.CloseIdleConnections()

	path := check.Path
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	port := check.Port
	if port == 0 {
		port = 80
	}

	url := fmt.Sprintf("%s://%s:%d/%s", scheme, address, port, path)
	req, err := http.NewRequest("GET", url, nil)
	if check.Host != "" {
		req.Host = check.Host
	}
	resp, err := client.Do(req)

	if err != nil {
		return false, fmt.Sprintf("GET: %s:%d %s %v", address, port, url, resp)
	}

	defer resp.Body.Close()

	//_, err = ioutil.ReadAll(resp.Body)

	exp := int(check.Expect)

	if exp == 0 {
		exp = 200
	}

	if resp.StatusCode != exp {
		return false, fmt.Sprintf("%d: %s:%s %s %v", resp.StatusCode, address, port, url, resp)
	}

	return true, ""
}
