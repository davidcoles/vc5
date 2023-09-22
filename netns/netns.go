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

	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/monitor/healthchecks"
	"github.com/davidcoles/vc5/types"
)

type Check = healthchecks.Check

var client *http.Client

type probe struct {
	IP     types.IP4
	Scheme string
	Check  Check
}

type response struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func Spawn(netns string, args ...string) {
	for {
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

func Probe(path string, ip types.IP4, scheme string, check Check) (bool, string) {

	if path == "" {
		return false, "No socket given"
	}

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

	if check.Port == 0 {
		panic("oops")
	}

	p := probe{IP: ip, Scheme: scheme, Check: check}

	buff := new(bytes.Buffer)

	err := json.NewEncoder(buff).Encode(&p)

	if err != nil {
		return false, "Internal error marshalling probe: " + err.Error()
	}

	resp, err := client.Post("http://unix/", "application/octet-stream", buff)

	if err != nil {
		return false, "Internal error contacting netns daemon: " + err.Error()
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("Internal HTTP error contacting netns daemon: %d", resp.StatusCode)
	}

	var v response

	err = json.Unmarshal(body, &v)

	if err != nil {
		return false, "Internal error unmarshalling probe response - " + err.Error()
	}

	return v.OK, v.Message
}

/**********************************************************************/

func Server(path string, ip string) {
	log.Println("RUNNING", path)

	wrong := []byte(`{"ok": false, "message":"all kinds of wrong"}`)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		c, _, err := reader.ReadRune()

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(c)
	}()

	os.Remove(path)

	syn := Syn(ip)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			js, err := json.Marshal(&response{OK: false, Message: "Couldn't read probe: " + err.Error()})
			if err != nil {
				w.Write(wrong)
			} else {
				w.Write(js)
			}
			return
		}

		var p probe

		err = json.Unmarshal(body, &p)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			js, err := json.Marshal(&response{OK: false, Message: "Couldn't unmarshal probe: " + err.Error()})
			if err != nil {
				w.Write(wrong)
			} else {
				w.Write(js)
			}
			return
		}

		resp := p.probe(syn)

		js, err := json.Marshal(&resp)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(wrong)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(js)

	})

	s, err := net.Listen("unix", path)

	if err != nil {
		log.Fatal(err)
	}

	server := http.Server{}

	log.Fatal(server.Serve(s))
}

func (p *probe) httpget() (bool, string) {
	check := p.Check

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
		return false, "Port is 0"
	}

	url := fmt.Sprintf("%s://%s:%d/%s", p.Scheme, p.IP, port, path)
	req, err := http.NewRequest("GET", url, nil)
	if check.Host != "" {
		req.Host = check.Host
	}

	resp, err := client.Do(req)

	if err != nil {
		return false, err.Error()
	}

	defer resp.Body.Close()

	ioutil.ReadAll(resp.Body)

	exp := int(check.Expect)

	if exp == 0 {
		exp = 200
	}

	return resp.StatusCode == exp, resp.Status
}

func (p *probe) synprobe(syn *SynChecks) (bool, string) {
	addr := p.IP.String()
	port := p.Check.Port

	if port == 0 {
		return false, "Port is 0"
	}

	return syn.Probe(addr, port), ""
}

func (p *probe) dnsprobe() (bool, string) {
	addr := p.IP.String()
	port := p.Check.Port

	if port == 0 {
		return false, "Port is 0"
	}

	return monitor.DNSQuery(addr, port), ""
}

//func tcpdial(foo probe) (bool, string) {
func (p *probe) tcpdial() (bool, string) {
	addr := p.IP.String()
	port := p.Check.Port

	if port == 0 {
		return false, "Port is 0"
	}

	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return false, fmt.Sprint(err)
	}

	one := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	//c.SetReadDeadline(time.Now())
	n, err := c.Read(one)
	c.Close()

	//log.Println(n, err)

	if err == nil && n != 0 {
		return true, ""
	}

	if err == io.EOF {
		return false, fmt.Sprint(err)
	}

	switch err := err.(type) {
	case net.Error:
		if err.Timeout() {
			// Port likely open and waiting for us to send input
			//log.Println("This was a net.Error with a Timeout")
			return true, ""
		}
	}

	return false, fmt.Sprint(err)
}

//func (p *probe) probe(syn *SynChecks) (bool, string) {
func (p *probe) probe(syn *SynChecks) response {
	//fmt.Println(p)

	var ok bool
	var st string

	switch p.Scheme {
	case "http":
		ok, st = p.httpget()
	case "https":
		ok, st = p.httpget()
	case "syn":
		ok, st = p.synprobe(syn)
	case "tcp":
		ok, st = p.tcpdial()
	case "dns":
		ok, st = p.dnsprobe()
	default:
		st = "Unknown probe type"
	}

	return response{OK: ok, Message: st}
}
