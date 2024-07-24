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

type KV = map[string]any

type index = int64
type secret string

func (s secret) MarshalText() ([]byte, error) { return []byte("************"), nil }
func (s *secret) String() string              { return "************" }

// old config, to be deprecated
type logging struct {
	Syslog        bool          `json:"syslog,omitempty"`
	Slack         secret        `json:"slack,omitempty"`
	Teams         secret        `json:"teams,omitempty"`
	Alert         uint8         `json:"alert,omitempty"`
	Elasticsearch Elasticsearch `json:"elasticsearch,omitempty"`
}

func (l *logging) logging() Logging {
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

type LogStats struct {
	ElasticsearchErrors uint64 `json:"elasticsearch_errors"`
	WebhookErrors       uint64 `json:"webhook_errors"`
}

func level(l uint8) string {
	a := []string{"EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"}

	if int(l) < len(a) {
		return a[l]
	}

	return "UNKNOWN"
}

type parent interface {
	log(uint8, string, ...any)
}

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
