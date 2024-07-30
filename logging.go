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
}

type Sink = sink
type sink struct {
	e chan *ent
	l chan Logging

	webhook atomic.Uint64
	elastic atomic.Uint64
}

func (s *sink) Sub(f string) *sub          { return &sub{parent: s, facility: f} }
func (s *sink) sub(f string) *sub          { return &sub{parent: s, facility: f} }
func (s *sink) EMERG(f string, a ...any)   { s.log(EMERG, f, a...) }
func (s *sink) ALERT(f string, a ...any)   { s.log(ALERT, f, a...) }
func (s *sink) CRIT(f string, a ...any)    { s.log(CRIT, f, a...) }
func (s *sink) ERR(f string, a ...any)     { s.log(ERR, f, a...) }
func (s *sink) WARNING(f string, a ...any) { s.log(WARNING, f, a...) }
func (s *sink) NOTICE(f string, a ...any)  { s.log(NOTICE, f, a...) }
func (s *sink) INFO(f string, a ...any)    { s.log(INFO, f, a...) }
func (s *sink) DEBUG(f string, a ...any)   { s.log(DEBUG, f, a...) }

type LogStats struct {
	ElasticsearchErrors uint64 `json:"elasticsearch_errors"`
	WebhookErrors       uint64 `json:"webhook_errors"`
}

func (s *sink) Stats() LogStats {
	return LogStats{
		ElasticsearchErrors: s.elastic.Load(),
		WebhookErrors:       s.webhook.Load(),
	}
}

func (s *sink) log(lev uint8, facility string, a ...any) {
	level := level(lev)

	now := time.Now()
	text := fmt.Sprintln(a...)

	if len(text) > 0 {
		// chop off the trailing newline
		l := len(text) - 1
		text = text[0:l]
	}

	kv := KV{}

	if len(a) == 1 {
		e := a[0]

		if k, ok := e.(KV); ok {

			kv = k
			var t []string
			for k, v := range kv {
				t = append(t, fmt.Sprintf("%s:%v", k, v))
			}
			sort.Strings(t)
			text = strings.Join(t, " ")
		} else {
			kv["text"] = text
		}
	} else {
		kv["text"] = text
	}

	kv["date"] = now.UnixNano() / int64(time.Millisecond)
	kv["level"] = level.String()
	kv["facility"] = facility

	js, _ := json.Marshal(kv)

	s.e <- &ent{text: text, json: js, level: level, facility: facility, time: now}
}

func (s *sink) Get(start uint64) (h []entry) {
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
	s.l <- l
}

func (s *sink) Start(l Logging) {
	s.e = make(chan *ent, 1000)
	s.l = make(chan Logging, 1000)

	go func() {
		// Not using full UnixNano here because large integers cause an
		// overflow in jq(1) which I often use for highlighting JSON
		// and it confuses me when the numbers are wrong!
		id := uint64(time.Now().UnixNano() / 1000000)

		host, _ := os.Hostname()
		if host == "" {
			host = fmt.Sprintf("%d", time.Now().UnixNano())
		}

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
				e.host = host
				e.id = id
				id++

				// send to console
				if console != nil && e.level < DEBUG {
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
					if e.level <= v.Level {
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
	//EMERG(f string, a ...any)
	ALERT(f string, a ...any)
	CRIT(f string, a ...any)
	ERR(f string, a ...any)
	WARNING(f string, a ...any)
	NOTICE(f string, a ...any)
	INFO(f string, a ...any)
	DEBUG(f string, a ...any)
}

type parent interface {
	log(uint8, string, ...any)
}

type Sub = sub
type sub struct {
	parent   parent
	facility string
}

func (l *sub) log(n uint8, s string, a ...any) { l.parent.log(n, l.facility+"."+s, a...) }
func (l *sub) EMERG(s string, a ...any)        { l.log(EMERG, s, a...) }
func (l *sub) ALERT(s string, a ...any)        { l.log(ALERT, s, a...) }
func (l *sub) CRIT(s string, a ...any)         { l.log(CRIT, s, a...) }
func (l *sub) ERR(s string, a ...any)          { l.log(ERR, s, a...) }
func (l *sub) WARNING(s string, a ...any)      { l.log(WARNING, s, a...) }
func (l *sub) NOTICE(s string, a ...any)       { l.log(NOTICE, s, a...) }
func (l *sub) INFO(s string, a ...any)         { l.log(INFO, s, a...) }
func (l *sub) DEBUG(s string, a ...any)        { l.log(DEBUG, s, a...) }

func (l *sub) BGPPeer(peer string, params bgp.Parameters, add bool) {
	if add {
		l.NOTICE("add", KV{"peer": peer})
	} else {
		l.NOTICE("remove", KV{"peer": peer})
	}
}

func (l *sub) BGPSession(peer string, local bool, reason string) {
	if local {
		l.NOTICE("local", KV{"peer": peer, "reason": reason})
	} else {
		l.ERR("remote", KV{"peer": peer, "reason": reason})
	}
}
