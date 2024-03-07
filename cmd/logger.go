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
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
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

var HOSTNAME string

type KV = map[string]any

type entry struct {
	Indx index  `json:"indx"`
	Time int64  `json:"time"`
	Text string `json:"text"`
}

type secret string

func (s secret) MarshalText() ([]byte, error) { return []byte("************"), nil }
func (s *secret) String() string              { return "************" }

type logger struct {
	Slack         secret        `json:"slack,omitempty"`
	Teams         secret        `json:"teams,omitempty"`
	Alert         uint8         `json:"alert,omitempty"`
	Elasticsearch Elasticsearch `json:"elasticsearch,omitempty"`

	mutex   sync.Mutex
	index   index
	count   uint64
	history []entry

	slack chan string
	teams chan string
}

type index = int64

func init() {
	HOSTNAME, _ = os.Hostname()
	if HOSTNAME == "" {
		HOSTNAME = fmt.Sprintf("%d", time.Now().UnixNano())
	}
}

type LogStats struct {
	ElasticsearchErrors uint64 `json:"elasticsearch_errors,omitempty"`
}

func (l *logger) Stats() LogStats {
	return LogStats{
		ElasticsearchErrors: l.Elasticsearch.Fail(),
	}
}

func (l *logger) console(text string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.index == 0 {
		// Not using full UnixNano here because large integers cause an
		// overflow in jq(1) which I often use for highlighting JSON
		// and it confuses me when the numbers are wrong!
		l.index = index(time.Now().UnixNano() / 1000000)
	}

	l.index++

	l.history = append(l.history, entry{Indx: l.index, Text: text, Time: time.Now().Unix()})
	for len(l.history) > 1000 {
		l.history = l.history[1:]
	}
}

func (l *logger) log(lev uint8, f string, a ...any) {

	text := fmt.Sprintln(a...)

	if len(text) > 0 {
		// chop off the trailing newline
		l := len(text) - 1
		text = text[0:l]
	}

	date := time.Now().UnixNano() / int64(time.Millisecond)

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

	kv["date"] = date
	kv["level"] = level(lev)
	kv["facility"] = f
	kv["hostname"] = HOSTNAME

	js, err := json.MarshalIndent(&kv, " ", " ")

	if err != nil {
		kv := KV{}
		kv["date"] = date
		kv["text"] = text
		kv["level"] = level(lev)
		kv["facility"] = f
		kv["hostname"] = HOSTNAME

		js, _ = json.MarshalIndent(&kv, " ", " ")
	}

	if lev < DEBUG {
		l.console(level(lev) + " " + f + " " + text)
	}

	if lev <= l.Alert {
		l.sendSlack(text)
		l.sendTeams(text)
	}

	l.Elasticsearch.log(string(js), HOSTNAME)

	if l.elasticAlert() {
		l.sendSlack("Elasticsearch logging is failing")
	}
}

func (l *logger) elasticAlert() bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.count == 0 {
		l.count = 1
	}

	fails := l.Elasticsearch.Fail()

	if fails >= l.count {
		l.count *= 10
		return true
	}

	return false
}

func (l *logger) sendSlack(text string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.Slack == "" {
		return
	}

	if l.slack == nil {
		l.slack = webhooks("Slack", l.Slack)
	}

	select {
	case l.slack <- text:
	default:
		l.slack = nil
		log.Println("Slack channel blocked")
	}
}

func (l *logger) sendTeams(text string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.Teams == "" {
		return
	}

	if l.teams == nil {
		l.teams = webhooks("Teams", l.Teams)
	}

	select {
	case l.teams <- text:
	default:
		l.teams = nil
		log.Println("Teams channel blocked")
	}
}

func webhooks(name string, url secret) chan string {
	c := make(chan string, 1000)

	go func() {
		for m := range c {
			if !webhook(url, m) {
				log.Printf("Failed to write log to %s: %s\n", name, m)
			}
		}
	}()

	return c
}

func webhook(dest secret, text string) bool {
	type slack struct {
		Text string `json:"text"`
	}

	js, _ := json.Marshal(&slack{Text: fmt.Sprintf("%s: %s", HOSTNAME, text)})

	res, err := http.Post(string(dest), "application/json", bytes.NewReader(js))

	if err != nil {
		return false
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false
	}

	return true
}

func (l *logger) get(start index) (s []entry) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for n := len(l.history) - 1; n > 0; n-- {
		e := l.history[n]
		if e.Indx <= start {
			break
		}
		s = append(s, e)
	}

	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return
}

func level(l uint8) string {
	a := []string{"EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"}

	if int(l) < len(a) {
		return a[l]
	}

	return "UNKNOWN"
}

func (l *logger) sub(f string) *sub { return &sub{parent: l, facility: f} }

func (l *logger) EMERG(s string, a ...any)   { l.log(EMERG, s, a...) }
func (l *logger) ALERT(s string, a ...any)   { l.log(ALERT, s, a...) }
func (l *logger) CRIT(s string, a ...any)    { l.log(CRIT, s, a...) }
func (l *logger) ERR(s string, a ...any)     { l.log(ERR, s, a...) }
func (l *logger) WARNING(s string, a ...any) { l.log(WARNING, s, a...) }
func (l *logger) NOTICE(s string, a ...any)  { l.log(NOTICE, s, a...) }
func (l *logger) INFO(s string, a ...any)    { l.log(INFO, s, a...) }
func (l *logger) DEBUG(s string, a ...any)   { l.log(DEBUG, s, a...) }

type sub struct {
	parent   *logger
	facility string
}

func (l *sub) log(n uint8, s string, a ...any) { l.parent.log(n, l.facility+"."+s, a...) }

func (l *sub) EMERG(s string, a ...any)   { l.log(EMERG, s, a...) }
func (l *sub) ALERT(s string, a ...any)   { l.log(ALERT, s, a...) }
func (l *sub) CRIT(s string, a ...any)    { l.log(CRIT, s, a...) }
func (l *sub) ERR(s string, a ...any)     { l.log(ERR, s, a...) }
func (l *sub) WARNING(s string, a ...any) { l.log(WARNING, s, a...) }
func (l *sub) NOTICE(s string, a ...any)  { l.log(NOTICE, s, a...) }
func (l *sub) INFO(s string, a ...any)    { l.log(INFO, s, a...) }
func (l *sub) DEBUG(s string, a ...any)   { l.log(DEBUG, s, a...) }

type Logger = *sub
