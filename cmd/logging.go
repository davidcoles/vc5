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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type Webhook struct {
	Level uint8  `json:"level,omitempty"`
	Type  string `json:"type,omitempty"`
	ent   chan ent
}

type Logging struct {
	Elasticsearch Elasticsearch      `json:"elasticsearch,omitempty"`
	Webhooks      map[secret]Webhook `json:"webhooks,omitempty"`
	Syslog        bool               `json:"syslog,omitempty"`
}

type sink struct {
	e chan *ent
	l chan Logging

	webhook atomic.Uint64
	elastic atomic.Uint64
}

type ent struct {
	id   uint64
	host string

	level    uint8
	facility string
	text     string
	json     []byte
	time     time.Time

	//es  *Elasticsearch
	typ string

	history []entry
	get     chan bool
	start   int64
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
		fmt.Println(err)
		return false
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		fmt.Println(res.StatusCode)
		return false
	}

	return true
}

func webhook_(url string) chan ent {
	c := make(chan ent, 1000)
	go func() {
		for l := range c {
			// could batch here
			m := payload(l)
			deliver(url, m)
		}
	}()
	return c
}

func (s *sink) _log(lev uint8, facility string, a ...any) {

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
	kv["level"] = level(lev)
	kv["facility"] = facility

	js, _ := json.Marshal(kv)

	s.e <- &ent{text: text, json: js, level: lev, facility: facility, time: now}
}

func (s *sink) get(start index) (h []entry) {
	l := &ent{get: make(chan bool), start: start}
	s.e <- l
	<-l.get
	//return l.history
	h = l.history
	// reverse h ... simpler to do thing in Javascript, perhaps?
	for i, j := 0, len(h)-1; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	return h
}

func (s *sink) start(l Logging) {
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
					elastic = elasticsink(l.Elasticsearch, &(s.elastic))
				}
			}

			for k, v := range l.Webhooks {
				if _, ok := webhooks[k]; !ok {
					v.ent = webhook_(string(k))
					webhooks[k] = v
				}
			}

			for k, v := range webhooks {
				if _, ok := l.Webhooks[k]; !ok {
					close(v.ent)
					delete(webhooks, k)
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

				// send to webhooks
				for _, v := range webhooks {
					if e.level <= v.Level {
						e.typ = v.Type
						select {
						case v.ent <- *e: // copy by value, .typ won't get modified later
						default:
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
					}
				}
				// send to console
				if console != nil && e.level < DEBUG {
					select {
					case console <- e:
					default:
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

func elasticsink(es Elasticsearch, f *atomic.Uint64) chan ent {
	c := make(chan ent, 1000)

	err := es.start()

	if err != nil {
		return nil
	}

	go func() {
		for e := range c {
			if !es.log(e.host, e.id, e.json) {
				f.Add(1)
			}
		}
	}()

	return c
}

func history() chan *ent {
	c := make(chan *ent, 1000)

	go func() {
		var history []entry

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
				e.history = s
				close(e.get)
			} else {
				history = append(history, entry{Indx: int64(e.id), Text: e.text, Time: e.time.Unix()})
				for len(history) > 1000 {
					history = history[1:]
				}
			}
		}
	}()

	return c
}

func (s *sink) log(l uint8, f string, a ...any) { s._log(l, f, a...) }
func (s *sink) sub(f string) *sub               { return &sub{parent: s, facility: f} }
func (s *sink) EMERG(f string, a ...any)        { s.log(EMERG, f, a...) }
func (s *sink) ALERT(f string, a ...any)        { s.log(ALERT, f, a...) }
func (s *sink) CRIT(f string, a ...any)         { s.log(CRIT, f, a...) }
func (s *sink) ERR(f string, a ...any)          { s.log(ERR, f, a...) }
func (s *sink) WARNING(f string, a ...any)      { s.log(WARNING, f, a...) }
func (s *sink) NOTICE(f string, a ...any)       { s.log(NOTICE, f, a...) }
func (s *sink) INFO(f string, a ...any)         { s.log(INFO, f, a...) }
func (s *sink) DEBUG(f string, a ...any)        { s.log(DEBUG, f, a...) }

func (s *sink) Stats() LogStats {
	return LogStats{
		ElasticsearchErrors: s.elastic.Load(),
		WebhookErrors:       s.webhook.Load(),
	}
}

type logger interface {
	EMERG(f string, a ...any)
	ALERT(f string, a ...any)
	CRIT(f string, a ...any)
	ERR(f string, a ...any)
	WARNING(f string, a ...any)
	NOTICE(f string, a ...any)
	INFO(f string, a ...any)
	DEBUG(f string, a ...any)
}
