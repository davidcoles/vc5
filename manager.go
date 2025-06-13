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

package vc5

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	//"log"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davidcoles/bgp"
	"github.com/davidcoles/cue"
	"github.com/davidcoles/cue/mon"
)

type Manager struct {
	config      *Config
	Director    *cue.Director
	Balancer    Balancer
	Logs        *Sink
	WebRoot     string
	BGPLoopback uint16
	NAT         func(netip.Addr, netip.Addr) (netip.Addr, bool)
	Prober      func(netip.Addr, netip.Addr, Check) (bool, string)
	RouterID    [4]byte
	WebListener net.Listener
	Interval    uint8
	Learn       uint

	Address netip.Addr
	SNI     bool

	HardFail bool

	pool     *bgp.Pool
	mutex    sync.Mutex
	services servicemap
	summary  Summary
	vip      map[netip.Addr]state
	rib      []netip.Addr
}

type Check = mon.Check

func Monitor(addr netip.Addr, cic bool) (*mon.Mon, error) {
	m := &mon.Mon{
		IPv4:                 addr, // for SYN probes
		CloseIdleConnections: cic,
	}

	err := m.Init(nil)

	if err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) Probe(_ *mon.Mon, i mon.Instance, check mon.Check) (ok bool, diagnostic string) {

	vip := i.Service.Address
	rip := i.Destination.Address

	if m.NAT != nil {
		// if we're using NAT to reach the backend then map the VIP/RIP tuple to the NAT address
		rip, ok = m.NAT(vip, rip)
		if !ok {
			return false, "NAT lookup failed"
		}
	}

	return m.Prober(vip, rip, check)
}

func (m *Manager) Manage(ctx context.Context, cfg *Config) error {
	// mostly lifted from main.go - probably need a bit of rationalising

	m.config = cfg

	learn := time.Duration(m.Learn)
	if learn == 0 {
		learn = 1
	}

	start := time.Now()
	F := "vc5"

	m.Director = &cue.Director{
		Notifier: m,
		SNI:      m.SNI,
		Address:  m.Address,
	}

	if m.Prober != nil {
		m.Director.Prober = m
	}

	routerID := m.RouterID

	// If loopback BGP mode is enabled (m.BGPLoopback is the ASN that we should use) then override router ID
	if m.BGPLoopback > 0 {
		routerID = [4]byte{127, 0, 0, 1} // no sensible BGP daemon would ever use this, surely!
	}

	m.pool = bgp.NewPool(routerID, m.config.Bgp(m.BGPLoopback, true), nil, m.Logs.Sub("bgp"))

	if m.pool == nil {
		return fmt.Errorf("BGP pool fail")
	}

	if err := m.Director.Start(m.config.Parse()); err != nil {
		return err
	}

	old := map[Instance]Stats{}
	m.vip = map[netip.Addr]state{}
	m.summary, m.services, old = serviceStatus(m.config, m.Balancer, m.Director, nil)

	// Collect stats
	go func() {

		interval := m.Interval

		if interval == 0 {
			interval = 10
		}

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for {
			var summary Summary
			m.mutex.Lock()
			summary, m.services, old = serviceStatus(m.config, m.Balancer, m.Director, old)
			m.summary.Update(summary, start)
			m.mutex.Unlock()
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()

	// advertise VIPs via BGP
	go func() {
		timer := time.NewTimer(learn * time.Second)
		ticker := time.NewTicker(5 * time.Second)
		services := m.Director.Status()

		defer func() {
			ticker.Stop()
			timer.Stop()
			m.pool.RIB(nil)
			time.Sleep(2 * time.Second)
			m.pool.Close()
		}()

		var initialised bool
		for {
			select {
			case <-ctx.Done(): // shuting down
				return
			case <-ticker.C: // check for matured VIPs
				//m.mutex.Lock()
				//vipmap = VipLog(director.Status(), vipmap, config.Priorities(), logs)
				//m.mutex.Unlock()
			case <-m.Director.C: // a backend has changed state
				m.mutex.Lock()
				services = m.Director.Status()
				var manifests []Manifest
				for _, s := range services {
					manifests = append(manifests, Manifest(s))
				}
				err := m.Balancer.Configure(manifests)
				m.mutex.Unlock()
				if err != nil {
					// if the configuration failed then the system is in an corrupt state
					// so the best thing to do is exit? (set HardFail) - not default yet
					text := "Couldn't apply config: " + err.Error()
					if m.HardFail {
						m.Logs.Fatal(F, "manager", KV{"error.message": text})
					} else {
						m.Logs.Alert(ERR, F, "manager", KV{"error.message": text}, text)
					}
				}

			case <-timer.C:
				m.Logs.Alert(NOTICE, F, "learn-timer-expired", KV{}, "Learn timer expired")
				initialised = true
			}

			m.mutex.Lock()
			m.vip = vipState(services, m.vip, m.config.Priorities(), m.Logs, initialised)
			m.rib = adjRIBOut(m.vip, initialised)
			m.mutex.Unlock()

			m.pool.RIB(m.rib)
		}
	}()

	static := http.FS(STATIC)
	var fs http.FileSystem

	webroot := m.WebRoot

	if webroot != "" {
		fs = http.FileSystem(http.Dir(webroot))
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if fs != nil {
			file := r.URL.Path
			if file == "/" {
				file = "/index.html"
			}

			if f, err := fs.Open(file); err == nil {
				f.Close()
				http.FileServer(fs).ServeHTTP(w, r)
				return
			}
		}

		r.URL.Path = "static/" + r.URL.Path
		http.FileServer(static).ServeHTTP(w, r)
	})

	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {

		start, _ := strconv.ParseUint(r.URL.Path[5:], 10, 64)
		logs := m.Logs.Get(start)
		js, err := json.MarshalIndent(&logs, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/build.json", func(w http.ResponseWriter, r *http.Request) {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		js, err := json.MarshalIndent(info, " ", " ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/cue.json", func(w http.ResponseWriter, r *http.Request) {
		js, err := m.Cue()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		js, err := m.JSONStatus()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		js = append(js, 0x0a) // add a newline
		w.Write(js)
	})

	http.HandleFunc("/status.json.gz", func(w http.ResponseWriter, r *http.Request) {
		js, err := m.JSONStatus()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		js = append(js, 0x0a) // add a newline

		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		gz.Write(js)
		gz.Close()

		w.Write(b.Bytes())
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {

		names_, metrics_ := m.Balancer.Metrics()
		//w.Header().Set("Content-Type", "text/plain")

		metrics := m.Prometheus("vc5")
		w.Header().Set("Content-Type", "text/plain")

		for _, n := range names_ {
			w.Write([]byte(fmt.Sprintf("# TYPE xvs_%s counter\n", n)))
		}

		w.Write([]byte(strings.Join(metrics, "\n") + "\n"))

		for _, m := range metrics_ {
			w.Write([]byte(fmt.Sprintln("xvs_" + m)))
		}

	})

	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		m.mutex.Lock()
		js, err := json.MarshalIndent(m.config, " ", " ")
		m.mutex.Unlock()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		w.Write([]byte("\n"))
	})

	listener := m.WebListener
	if listener != nil {
		go func() {
			for {
				server := http.Server{}
				err := server.Serve(listener)
				m.Logs.Alert(ALERT, F, "webserver", KV{"error.message": err.Error()}, "Webserver exited: "+err.Error())
				time.Sleep(10 * time.Second)
			}
		}()
	}

	return nil
}

func (m *Manager) Configure(config *Config) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.Director.Configure(config.Parse())
	m.pool.Configure(config.Bgp(m.BGPLoopback, false))
	m.Logs.Configure(config.LoggingConfig())
	m.config = config
}

func (m *Manager) Cue() ([]byte, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return json.MarshalIndent(m.Director.Status(), " ", " ")
}

func (m *Manager) JSONStatus() ([]byte, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return jsonStatus(m.summary, m.services, m.vip, m.pool, m.rib, m.Logs.Stats())
}

func (m *Manager) Prometheus(s string) []string {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return Prometheus(s, m.services, m.summary, m.vip)
}

func jsonStatus(summary Summary, services servicemap, vips map[netip.Addr]state, pool *bgp.Pool, rib []netip.Addr, logstats LogStats) ([]byte, error) {
	return json.MarshalIndent(struct {
		Summary  Summary               `json:"summary"`
		Services servicemap            `json:"services"`
		BGP      map[string]bgp.Status `json:"bgp"`
		VIP      []vipstats            `json:"vip"`
		RIB      []netip.Addr          `json:"rib"`
		Logging  LogStats              `json:"logging"`
	}{
		Summary:  summary,
		Services: services,
		BGP:      pool.Status(),
		VIP:      vipStatus(services, vips),
		RIB:      rib,
		Logging:  logstats,
	}, " ", " ")
}

/**********************************************************************/
// notifications
/**********************************************************************/

func ms(s mon.Service) Service {
	return Service{Address: s.Address, Port: s.Port, Protocol: Protocol(s.Protocol)}
}

func md(d mon.Destination) Destination {
	return Destination{Address: d.Address, Port: d.Port}
}

// interface method called by mon when a destination's health status transitions up or down
func (m *Manager) Notify(instance mon.Instance, state bool) {
	text := fmt.Sprintf("Backend %s for service %s went %s", md(instance.Destination), ms(instance.Service), upDown(state))
	m.Logs.Alert(5, "healthcheck", "state", notifyLog(instance, state), text)
}

// interface method called by mon every time a round of checks for a service on a destination is completed
func (m *Manager) Result(instance mon.Instance, state bool, diagnostic string) {
	//m.Logs.Event(7, "healthcheck", "state", resultLog(instance, state, diagnostic))
	m.Logs.State("healthcheck", "state", resultLog(instance, state, diagnostic))
}

func (m *Manager) Check(instance mon.Instance, check string, round uint64, state bool, diagnostic string) {
	entry := checkLog(instance, state, diagnostic, check, round)
	if m.NAT != nil {
		nat, _ := m.NAT(instance.Service.Address, instance.Destination.Address)
		entry["destination.nat.ip"] = nat
	}
	m.Logs.Event(7, "healthcheck", "check", entry)
}

func notifyLog(instance mon.Instance, state bool) map[string]any {
	// https://www.elastic.co/guide/en/ecs/current/ecs-base.html
	// https://github.com/elastic/ecs/blob/main/generated/csv/fields.csv

	s := Service{Address: instance.Service.Address, Port: instance.Service.Port, Protocol: Protocol(instance.Service.Protocol)}
	d := Destination{Address: instance.Destination.Address, Port: instance.Destination.Port}

	return map[string]any{
		"service.state":       upDown(state),
		"service.ip":          s.Address.String(),
		"service.port":        instance.Service.Port,
		"service.protocol":    s.Protocol.String(),
		"service.address":     s.String(),
		"destination.ip":      d.Address.String(),
		"destination.port":    d.Port,
		"destination.address": d.String(),
	}
}

func resultLog(instance mon.Instance, status bool, diagnostic string) map[string]any {
	r := notifyLog(instance, status)
	r["diagnostic"] = diagnostic
	return r
}

func checkLog(instance mon.Instance, status bool, diagnostic string, check string, round uint64) map[string]any {
	r := resultLog(instance, status, diagnostic)
	r["check"] = check
	r["round"] = round
	return r
}

func adjRIBOut(vip map[netip.Addr]state, initialised bool) (r []netip.Addr) {
	for v, s := range vip {
		if initialised && s.up && time.Now().Sub(s.time) > time.Second*5 {
			r = append(r, v)
		}
	}
	return
}

/*
func VipMap(services []cue.Service) map[netip.Addr]bool {

	m := map[netip.Addr]bool{}

	for _, v := range cue.AllVIPs(services) {
		m[v] = false
	}

	for _, v := range cue.HealthyVIPs(services) {
		m[v] = true
	}

	fmt.Println(m)

	return m
}

func VipLog(services []cue.Service, old map[netip.Addr]bool, priorities map[netip.Addr]priority, logs Logger) map[netip.Addr]bool {

	f := "vip"

	m := VipMap(services)

	for vip, state := range m {

		severity := p2s(priorities[vip])

		if was, exists := old[vip]; exists {
			if state != was {
				logs.Alert(severity, f, "state", KV{"service.ip": vip, "service.state": upDown(state)})
			}
		} else {
			logs.Alert(INFO, f, "added", KV{"service.ip": vip, "service.state": upDown(state)})
		}

		logs.Event(DEBUG, f, "state", KV{"service.ip": vip, "service.state": upDown(state)})
	}

	for vip, _ := range old {
		if _, exists := m[vip]; !exists {
			logs.Alert(6, f, "removed", KV{"service.ip": vip})
		}
	}

	return m
}

*/
