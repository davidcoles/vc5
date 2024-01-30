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

package monitor

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/davidcoles/vc5/monitor/healthchecks"
)

var client *http.Client
var dialer *net.Dialer
var mu sync.Mutex

func init() {
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

type Probes struct {
	syn *SynChecks
}

func (c *Probes) Start(ip string) {
	c.syn = Syn(ip)
}

func (c *Probes) Check(vip IP4, rip IP4, check healthchecks.Check) (bool, string) {

	schema := string(check.Type)

	if check.Port == 0 {
		return false, "Port is zero"
	}

	switch schema {

	case "http":
		x, y := HTTPGet(schema, rip.String(), check)
		return x, y
	case "https":
		return HTTPGet(schema, rip.String(), check)
	case "dns":
		return DNSUDP(rip.String(), check.Port)
	case "dnstcp":
		return DNSTCP(rip.String(), check.Port)
	case "syn":
		return c.syn.Check(rip, check.Port)
	}

	return false, "not implemented"
}

func HTTPGet(scheme, ip string, check healthchecks.Check) (bool, string) {

	if check.Port == 0 {
		return false, "Port is zero"
	}

	method := "GET"

	switch check.Method.String() {
	case "HEAD":
		method = "HEAD"
	default:
	}

	defer client.CloseIdleConnections()

	path := check.Path

	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	url := fmt.Sprintf("%s://%s:%d/%s", scheme, ip, check.Port, path)
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		return false, err.Error()
	}

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
