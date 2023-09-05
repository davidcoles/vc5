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
	"time"

	"github.com/davidcoles/vc5/monitor/healthchecks"
)

type Probes struct {
	syn *SynChecks
}

func (c *Probes) Start(ip string) {
	c.syn = Syn(ip)
}

func (c *Probes) Check(vip IP4, rip IP4, nat IP4, schema string, check healthchecks.Check) (bool, string) {
	switch schema {

	case "http":
		return httpget(schema, rip.String(), check)
	case "https":
		return httpget(schema, rip.String(), check)
	case "dns":
		ok := dnsquery(rip.String(), fmt.Sprintf("%d", check.Port))
		return ok, ""
	case "syn":
		ok := c.syn.Probe(rip.String(), check.Port)
		return ok, ""
	}

	return false, "not implemented"
}

var client *http.Client

func httpget(scheme, ip string, check healthchecks.Check) (bool, string) {

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

	url := fmt.Sprintf("%s://%s:%d/%s", scheme, ip, port, path)
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