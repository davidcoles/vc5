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

package logger

import (
	"encoding/json"
	"fmt"
	"time"
)

type Logentry struct {
	Time  time.Time
	Level uint8
	Entry interface{}
	Ms    uint64
}

type Logger struct {
	history []Logentry
	channel chan Logentry
}

func NewLogger() *Logger {
	logger := Logger{channel: make(chan Logentry, 1000)}
	last := uint64(0)

	go func() {
		for e := range logger.channel {

			ms := uint64(e.Time.UnixNano() / 1000000)
			if ms <= last {
				ms = last + 1
			}
			last = ms
			e.Ms = ms

			logger.history = append(logger.history, e)

			for len(logger.history) > 1000 {
				logger.history = logger.history[1:]
			}
		}
	}()

	return &logger
}

func (l *Logger) Dump() []Logentry {
	return l.history
}

func (l *Logger) Since(t uint64) []Logentry {
	for i, v := range l.history {
		if v.Ms > t {
			return l.history[i:]
		}
	}
	return []Logentry{}
}

func (l *Logger) Text(level uint8) []string {
	var log []string
	for _, e := range l.history {
		if e.Level <= level {
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
	}
	return log
}

func (l *Logger) Append(e Logentry) {
	l.channel <- e
}

func (e *Logentry) String() string {
	var s string
	switch e.Entry.(type) {
	case string:
		s = e.Entry.(string)
	default:
		j, _ := json.Marshal(e.Entry)
		s = string(j)
	}

	return fmt.Sprintf("%s %d %s", e.Time.UTC().Format(time.UnixDate), e.Level, s)
	return fmt.Sprintf("%s %d %s", e.Time, e.Level, s)
	return s
}

func (l *Logger) Log(level uint8, entry interface{}) {
	e := Logentry{Time: time.Now(), Level: level, Entry: entry}
	//fmt.Println(e.String())
	l.Append(e)
}

func (l *Logger) EMERG(e interface{})   { l.Log(LOG_EMERG, e) }
func (l *Logger) ALERT(e interface{})   { l.Log(LOG_ALERT, e) }
func (l *Logger) CRIT(e interface{})    { l.Log(LOG_CRIT, e) }
func (l *Logger) ERR(e interface{})     { l.Log(LOG_ERR, e) }
func (l *Logger) WARNING(e interface{}) { l.Log(LOG_WARNING, e) }
func (l *Logger) NOTICE(e interface{})  { l.Log(LOG_NOTICE, e) }
func (l *Logger) INFO(e interface{})    { l.Log(LOG_INFO, e) }
func (l *Logger) DEBUG(e interface{})   { l.Log(LOG_DEBUG, e) }

const (
	LOG_EMERG   = 0 /* system is unusable */
	LOG_ALERT   = 1 /* action must be taken immediately */
	LOG_CRIT    = 2 /* critical conditions */
	LOG_ERR     = 3 /* error conditions */
	LOG_WARNING = 4 /* warning conditions */
	LOG_NOTICE  = 5 /* normal but significant condition */
	LOG_INFO    = 6 /* informational */
	LOG_DEBUG   = 7 /* debug-level messages */
)

//func (c *Controll) Log(level int, entry interface{}) {
//	c.logger.Log(level, entry)
//}
