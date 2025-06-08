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
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"os"
	//"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/davidcoles/cue/bgp"
)

const (
	EMERG   = 0
	ALERT   = 1
	CRIT    = 2
	ERR     = 3
	WARNING = 4
	NOTICE  = 5
	INFO    = 6
	DEBUG   = 7
)

// old config, to be deprecated
type Logging_ = logging
type logging struct {
	Syslog        bool          `json:"syslog,omitempty"`
	Slack         secret        `json:"slack,omitempty"`
	Teams         secret        `json:"teams,omitempty"`
	Alert         level         `json:"alert,omitempty"`
	Elasticsearch Elasticsearch `json:"elasticsearch,omitempty"`
}

func (l *logging) Logging() Logging {
	logging := Logging{
		Elasticsearch: l.Elasticsearch,
		Syslog:        l.Syslog,
	}

	logging.Webhooks = map[secret]Webhook{}

	if l.Teams != "" {
		logging.Webhooks[l.Teams] = Webhook{Level: l.Alert, Type: "teams"}
	}

	if l.Slack != "" {
		logging.Webhooks[l.Slack] = Webhook{Level: l.Alert, Type: "slack"}
	}

	return logging
}

type KV = map[string]any

type secret string

func (s secret) MarshalText() ([]byte, error) { return []byte("************"), nil }
func (s *secret) String() string              { return "************" }

type level uint8

func (l level) String() string {
	a := []string{"EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"}

	if int(l) < len(a) {
		return a[l]
	}

	return "UNKNOWN"
}

type Webhook struct {
	Level level  `json:"level,omitempty"`
	Type  string `json:"type,omitempty"`
	ent   chan ent
}

type Logging struct {
	Elasticsearch Elasticsearch      `json:"elasticsearch,omitempty"`
	Webhooks      map[secret]Webhook `json:"webhooks,omitempty"`
	Syslog        bool               `json:"syslog,omitempty"`
}

type entry struct {
	Indx uint64 `json:"indx"`
	Time int64  `json:"time"`
	Text string `json:"text"`
}

type ent struct {
	id   uint64
	host string

	level    level
	facility string
	text     string
	json     []byte
	time     time.Time

	es  *Elasticsearch
	typ string

	history []entry
	get     chan bool
	start   uint64
	alert   bool
}

func NewLogger(hostid string, l Logging) *Sink {
	logs := &Sink{HostID: hostid}
	logs.Start(l)
	return logs
}

type Sink = sink
type sink struct {
	HostID string

	e    chan *ent
	l    chan Logging
	host string

	webhook atomic.Uint64
	elastic atomic.Uint64
}

func (s *sink) Sub(f string) *sub                                         { return &sub{parent: s, facility: f} }
func (s *sink) sub(f string) *sub                                         { return &sub{parent: s, facility: f} }
func (s *sink) Event(n uint8, f, a string, e map[string]any)              { s.event(n, f, a, e) }
func (s *sink) Alert(n uint8, f, a string, e map[string]any, t ...string) { s.alert(n, f, a, e, t...) }
func (s *sink) State(f, a string, e map[string]any)                       { s.state(f, a, e) }

func (s *sink) Fatal(f string, a string, e map[string]any) {
	s.Alert(EMERG, f, a, e)
	time.Sleep(time.Second) // give log entry the chance to flush
	log.Fatal(fmt.Sprint(f, a, e))
}

type LogStats struct {
	ElasticsearchErrors uint64 `json:"elasticsearch_errors"`
	WebhookErrors       uint64 `json:"webhook_errors"`
}

func (s *sink) Stats() (_ LogStats) {
	if s == nil {
		return
	}
	return LogStats{
		ElasticsearchErrors: s.elastic.Load(),
		WebhookErrors:       s.webhook.Load(),
	}
}

const _EVENT = 0
const _STATE = 1
const _ALERT = 2

func (s *sink) state(facility string, action string, event map[string]any) {
	s._event(_STATE, DEBUG, facility, action, event)
}

func (s *sink) event(lev uint8, facility string, action string, event map[string]any) {
	s._event(_EVENT, lev, facility, action, event)
}

func (s *sink) alert(lev uint8, facility string, action string, event map[string]any, t ...string) {
	s._event(_ALERT, lev, facility, action, event, t...)
}

func (s *sink) _event(kind uint8, lev uint8, facility string, action string, event map[string]any, hrt ...string) {
	if s == nil {
		return
	}

	var alert bool

	level := level(lev)

	now := time.Now()

	reason, ok := event["reason"]

	if ok {
		delete(event, "reason")
		event["event.reason"] = reason.(string)
	}

	event["host.id"] = s.host
	event["date"] = now.UnixNano() / int64(time.Millisecond)
	event["@timestamp"] = now.UnixNano() / int64(time.Millisecond)
	event["level"] = level.String()
	event["event.module"] = facility
	event["event.action"] = action
	event["event.severity"] = uint8(level)

	switch kind {
	case _ALERT:
		event["event.kind"] = "alert"
		alert = true
	case _STATE:
		event["event.kind"] = "state"
	default:
		event["event.kind"] = "event"
	}

	var t []string
	for k, v := range event {
		switch k {
		case "date":
		case "@timestamp":
		default:
			t = append(t, fmt.Sprintf("%s:%v", k, v))
		}
	}
	sort.Strings(t)
	text := strings.Join(t, " ")

	if len(hrt) > 0 {
		text = hrt[0]
	}

	js, _ := json.Marshal(event)

	s.e <- &ent{text: text, json: js, level: level, facility: facility, time: now, alert: alert}
}

func (s *sink) Get(start uint64) (h []entry) {
	if s == nil {
		return
	}

	l := &ent{get: make(chan bool), start: start}
	s.e <- l
	<-l.get
	//return l.history
	h = l.history
	// reverse h ... simpler to do this in Javascript, perhaps?
	for i, j := 0, len(h)-1; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	return h
}

func (s *sink) Configure(l Logging) {
	if s == nil {
		return
	}
	s.l <- l
}

func (s *sink) Start(l Logging) {
	s.e = make(chan *ent, 1000)
	s.l = make(chan Logging, 1000)

	{
		host := s.HostID

		if host == "" {
			host, _ = os.Hostname()
		}

		if host == "" {
			host = fmt.Sprintf("%d", time.Now().UnixNano())
		}

		s.host = host
	}

	go func() {

		// Not using full UnixNano here because large integers cause an
		// overflow in jq(1) which I often use for highlighting JSON
		// and it confuses me when the numbers are wrong!
		id := uint64(time.Now().UnixNano() / 1000000)

		webhooks := map[secret]Webhook{}
		var elastic chan ent
		var syslog chan ent
		console := history()

		config := func(l Logging) {

			if l.Elasticsearch.Index == "" {
				if elastic != nil {
					close(elastic)
					elastic = nil
				}
			} else {
				if elastic == nil {
					elastic = elasticSink(l.Elasticsearch, &(s.elastic))
				} else {
					select {
					case elastic <- ent{es: &(l.Elasticsearch)}:
					default: // get rid of blocking channel
						close(elastic)
						elastic = elasticSink(l.Elasticsearch, &(s.elastic))
					}
				}
			}

			for k, v := range l.Webhooks {
				if x, ok := webhooks[k]; !ok {
					// does not exist
					v.ent = webhookSink(string(k), &(s.webhook))
					webhooks[k] = v
				} else {
					// does exist - update
					x.Type = v.Type
					x.Level = v.Level
					webhooks[k] = x
				}
			}

			for k, v := range webhooks {
				if _, ok := l.Webhooks[k]; !ok {
					close(v.ent)
					delete(webhooks, k)
				}
			}

			if l.Syslog {
				if syslog == nil {
					syslog = syslogSink()
				}
			} else {
				if syslog != nil {
					close(syslog)
					syslog = nil
				}
			}

		}

		config(l)

		for {
			select {
			case l := <-s.l:
				config(l)

			case e := <-s.e:
				e.host = s.host
				e.id = id
				id++

				// send to console
				if console != nil && ((e.alert && e.level < DEBUG) || e.get != nil) {
					select {
					case console <- e:
					default:
					}
				}

				if e.get != nil {
					break // e.get is only used to get history info for the console - it's not a real log
				}

				// send to webhooks
				for _, v := range webhooks {
					if e.alert && e.level <= v.Level {
						e.typ = v.Type
						select {
						case v.ent <- *e: // copy by value, .typ won't get modified later
						default:
							s.webhook.Add(1)
						}
					}
				}

				// send to syslog
				if syslog != nil {
					select {
					case syslog <- *e:
					default:
					}
				}

				// send to elasticsearch
				if elastic != nil {
					select {
					case elastic <- *e:
					default:
						s.elastic.Add(1)
					}
				}
			}
		}
	}()
}

func simpleMessage(lines ...string) ([]byte, error) {
	type slack struct {
		Text string `json:"text"`
	}
	m := strings.Join(lines, "\n")

	return json.Marshal(&slack{Text: m})
}

func adaptiveCard(lines ...string) ([]byte, error) {

	body := []any{}

	for _, text := range lines {
		body = append(body, map[string]any{"type": "TextBlock", "text": text, "wrap": true})
	}

	return json.MarshalIndent(map[string]any{
		"type": "message",
		"attachments": []any{
			map[string]any{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"contentUrl":  nil,
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.2",
					"body":    body,
				},
			},
		},
	}, " ", " ")
}

func payload(l ent) []byte {
	switch l.typ {
	case "teams":
		js, _ := adaptiveCard(fmt.Sprintf("%s %s[%s]:", l.host, l.facility, level(l.level)), l.text)
		return js
	case "slack":
		fallthrough
	default:
		js, _ := simpleMessage(fmt.Sprintf("%s %s[%s]: %s", l.host, l.facility, level(l.level), l.text))
		return js
	}

	return nil
}

func deliver(dest string, js []byte) bool {

	res, err := http.Post(string(dest), "application/json", bytes.NewReader(js))

	if err != nil {
		return false
	}

	defer res.Body.Close()

	// Slack returns 200, Teams returns 202 - return true if either of these
	return res.StatusCode == 200 || res.StatusCode == 202
}

func webhookSink(url string, fail *atomic.Uint64) chan ent {
	c := make(chan ent, 1000)
	go func() {
		for l := range c {
			// could batch here
			m := payload(l)
			if !deliver(url, m) {
				fail.Add(1)
			}
		}
	}()
	return c
}

func syslogSink() chan ent {

	s, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, "")

	if err != nil {
		return nil
	}

	c := make(chan ent, 1000)

	go func() {
		// This is probably overkill, but remember hearing something about syslog blocking threads.
		/*
			orig := runtime.GOMAXPROCS(0)

			runtime.GOMAXPROCS(orig + 1)

			procs := runtime.GOMAXPROCS(0)

			fmt.Println("procs", orig, procs)

			runtime.LockOSThread()

			defer func() {
				runtime.UnlockOSThread()
				defer runtime.GOMAXPROCS(orig)
				defer fmt.Println("EXITING")
			}()
		*/

		for e := range c {
			switch e.level {
			case EMERG:
				err = s.Emerg(e.text)
			case ALERT:
				err = s.Alert(e.text)
			case CRIT:
				err = s.Crit(e.text)
			case ERR:
				err = s.Err(e.text)
			case WARNING:
				err = s.Warning(e.text)
			case NOTICE:
				err = s.Notice(e.text)
			case INFO:
				err = s.Info(e.text)
			case DEBUG:
				err = s.Debug(e.text)
			}
		}
	}()

	return c
}

func elasticSink(es Elasticsearch, f *atomic.Uint64) chan ent {
	c := make(chan ent, 1000)

	err := es.start()

	if err != nil {
		return nil
	}

	go func() {
		for e := range c {

			if e.es != nil { // reconfigure
				es = *(e.es)
				es.start()
			} else {
				if !es.log(e.host, e.id, e.json) {
					f.Add(1)
				}
			}
		}
	}()

	return c
}

func history() chan *ent {
	c := make(chan *ent, 1000)

	go func() {
		var history []entry // oldest log entry first

		for e := range c {
			if e.get != nil {
				// find entries newer than l.start
				var s []entry
				//for n := len(history) - 1; n > 0; n-- { // FIXME n >= 0 maybe ?
				for n := len(history) - 1; n >= 0; n-- {
					h := history[n]
					if h.Indx <= e.start {
						break
					}
					s = append(s, h)
				}
				e.history = s // s will be in order of newest to oldest
				close(e.get)
			} else {
				history = append(history, entry{Indx: e.id, Text: e.text, Time: e.time.Unix()})
				for len(history) > 1000 {
					history = history[1:]
				}
			}
		}
	}()

	return c
}

type Logger interface {
	State(f, a string, e map[string]any)
	Event(l uint8, f, a string, e map[string]any)
	Alert(l uint8, f, a string, e map[string]any, text ...string) // a single text arg is used for human readable log lines if present
}

type parent interface {
	state(f, a string, e map[string]any)
	event(l uint8, f, a string, e map[string]any)
	alert(l uint8, f, a string, e map[string]any, t ...string)
}

type Sub = sub
type sub struct {
	parent   parent
	facility string
}

func (l *sub) State(f, a string, e map[string]any) { l.parent.state(l.facility+"."+f, a, e) }
func (l *sub) Event(n uint8, f, a string, e map[string]any) {
	l.parent.event(n, l.facility+"."+f, a, e)
}
func (l *sub) Alert(n uint8, f, a string, e map[string]any, t ...string) {
	l.parent.alert(n, l.facility+"."+f, a, e, t...)
}

func (l *sub) BGPPeer(peer string, params bgp.Parameters, add bool) {
	F := "peer"
	if add {
		//l.NOTICE("add", KV{"peer": peer})
		l.Event(NOTICE, F, "add", KV{"server.address": peer})
	} else {
		//l.NOTICE("remove", KV{"peer": peer})
		l.Event(NOTICE, F, "remove", KV{"server.address": peer})
	}
}

func (l *sub) BGPSession(peer string, local bool, reason string) {
	F := "session"
	text := fmt.Sprintf("BGP session with %s: %s", peer, reason)
	if local {
		//l.NOTICE("local", KV{"peer": peer, "reason": reason})
		l.Alert(NOTICE, F, "local", KV{"server.address": peer, "error.message": reason}, text)
	} else {
		//l.ERR("remote", KV{"peer": peer, "reason": reason})
		l.Alert(ERR, F, "remote", KV{"server.address": peer, "error.message": reason}, text)
	}
}
