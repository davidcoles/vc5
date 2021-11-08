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
	"encoding/json"
	"fmt"
	"time"
)

type Logentry struct {
	Time  time.Time
	Level int
	Entry interface{}
}

type logger struct {
	history []Logentry
}

func NewLogger() *logger {
	return &logger{}
}

func (l *logger) Dump() interface{} {
	return l.history
}

func (l *logger) Text() []string {
	var log []string
	for _, e := range l.history {
		var t string
		switch e.Entry.(type) {
		case string:
			t = e.Entry.(string)
		default:
			j, _ := json.Marshal(e.Entry)
			t = string(j)
		}

		log = append(log, fmt.Sprintf("%s: %s\n", e.Time.Format(time.UnixDate), t))
	}

	return log
}

func (l *logger) Log(level int, entry interface{}) {
	l.history = append(l.history, Logentry{Time: time.Now(), Level: level, Entry: entry})
	for len(l.history) > 1000 {
		l.history = l.history[1:]
	}
}

//func (c *Controll) Log(level int, entry interface{}) {
//	c.logger.Log(level, entry)
//}
