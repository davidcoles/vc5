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

type response struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type probe struct {
	IP     types.IP4
	Scheme string
	Check  Check
}

func (p *probe) probe(syn *monitor.SynChecks) (bool, string) {

	switch p.Scheme {
	case "http":
		return monitor.HTTPGet(p.Scheme, p.IP.String(), p.Check)
	case "https":
		return monitor.HTTPGet(p.Scheme, p.IP.String(), p.Check)
	case "syn":
		return syn.Check(p.IP, p.Check.Port)
	case "dns":
		return monitor.DNSUDP(p.IP.String(), p.Check.Port)
	case "dnstcp":
		return monitor.DNSTCP(p.IP.String(), p.Check.Port)
	}

	return false, "Unknown probe type"
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

type Client struct {
	path   string
	client *http.Client
}

func NewClient(path string) *Client {
	c := &Client{path: path}

	c.client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", path)
			},
		},
	}

	return c
}

func (c *Client) Path() string { return c.path }

func (c *Client) Probe(ip types.IP4, check Check) (bool, string) {

	defer c.client.CloseIdleConnections()

	if check.Port == 0 {
		return false, "Port is zero"
	}

	p := probe{IP: ip, Scheme: check.Type, Check: check}

	buff := new(bytes.Buffer)

	err := json.NewEncoder(buff).Encode(&p)

	if err != nil {
		return false, "Internal error marshalling probe: " + err.Error()
	}

	resp, err := c.client.Post("http://unix/", "application/octet-stream", buff)

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

	syn := monitor.SynServer(ip, true) // true: send RSTs

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

		ok, msg := p.probe(syn)
		resp := response{OK: ok, Message: msg}

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

/*
func (p *probe) synprobe(syn *monitor.SynChecks) (bool, string) {

	if p.Check.Port == 0 {
		return false, "Port is 0"
	}

	return syn.Check(p.IP, p.Check.Port)
}

func (p *probe) dnsudp() (bool, string) {
	addr := p.IP.String()
	port := p.Check.Port

	if port == 0 {
		return false, "Port is 0"
	}

	return monitor.DNSUDP(addr, port)
}

func (p *probe) dnstcp() (bool, string) {
	addr := p.IP.String()
	port := p.Check.Port

	if port == 0 {
		return false, "Port is 0"
	}

	return monitor.DNSTCP(addr, port)
}

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
	n, err := c.Read(one)
	c.Close()

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

func (p *probe) httpget() (bool, string) {
	return monitor.HTTPGet(p.Scheme, p.IP.String(), p.Check)
}


func (p *probe) probe(syn *monitor.SynChecks) response {

	var ok bool
	var st string

	switch p.Scheme {
	case "http":
		ok, st = monitor.HTTPGet(p.Scheme, p.IP.String(), p.Check)
	case "https":
		ok, st = monitor.HTTPGet(p.Scheme, p.IP.String(), p.Check)
	case "syn":
		ok, st = syn.Check(p.IP, p.Check.Port)
	case "dns":
		ok, st = monitor.DNSUDP(p.IP.String(), p.Check.Port)
	case "dnstcp":
		ok, st = monitor.DNSTCP(p.IP.String(), p.Check.Port)
	default:
		st = "Unknown probe type"
	}

	return response{OK: ok, Message: st}
}

*/
