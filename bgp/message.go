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

package bgp

func updateMessage(ip IP, asn uint16, p Parameters, external bool, m map[IP]bool) message {
	return message{mtype: M_UPDATE, body: bgpupdate(p.SourceIP, p.ASNumber, external, p.LocalPref, p.MED, p.Communities, m)}
}

func openMessage(as uint16, ht uint16, id IP) message {
	return message{mtype: M_OPEN, open: open{version: 4, as: as, ht: ht, id: id}}
}

func keepaliveMessage() message {
	return message{mtype: M_KEEPALIVE}
}

func notificationMessage(code, sub uint8) message {
	return message{mtype: M_NOTIFICATION, notification: notification{code: code, sub: sub}}
}

func shutdownMessage(d string) message {
	return message{mtype: M_NOTIFICATION, notification: notification{
		code: CEASE, sub: ADMINISTRATIVE_SHUTDOWN, data: []byte(d),
	}}
}

func bgpupdate(myip IP, asn uint16, external bool, local_pref uint32, med uint32, communities []Community, status map[IP]bool) []byte {

	// Currently 256 avertisements results in a BGP UPDATE message of ~1307 octets
	// Maximum message size if 4096 octets so will need some way to split larger
	// avertisements down - maybe if the #prefixes is > 512 then split in two and
	// retry each half recurseively

	var withdrawn []byte
	var advertise []byte

	for k, v := range status {
		if v {
			advertise = append(advertise, 32, k[0], k[1], k[2], k[3]) // 32 bit prefix
		} else {
			withdrawn = append(withdrawn, 32, k[0], k[1], k[2], k[3]) // 32 bit prefix
		}
	}

	// <attribute type, attribute length, attribute value> [data ...]
	// (Well-known, Transitive, Complete, Regular length), 1(ORIGIN), 1(byte), 0(IGP)
	origin := []byte{WTCR, ORIGIN, 1, IGP}

	// (Well-known, Transitive, Complete, Regular length). 2(AS_PATH), 0(bytes, if iBGP - may get updated)
	as_path := []byte{WTCR, AS_PATH, 0}

	if external {
		// Each AS path segment is represented by a triple <path segment type, path segment length, path segment value>
		as_sequence := []byte{AS_SEQUENCE, 1} // AS_SEQUENCE(2), 1 ASN
		as_sequence = append(as_sequence, htons(asn)...)
		as_path = append(as_path, as_sequence...)
		as_path[2] = byte(len(as_sequence)) // update length field
	}

	// (Well-known, Transitive, Complete, Regular length), NEXT_HOP(3), 4(bytes)
	next_hop := append([]byte{WTCR, NEXT_HOP, 4}, myip[:]...)

	path_attributes := []byte{}
	path_attributes = append(path_attributes, origin...)
	path_attributes = append(path_attributes, as_path...)
	path_attributes = append(path_attributes, next_hop...)

	// rfc4271: A BGP speaker MUST NOT include this attribute in UPDATE messages it sends to external peers ...
	if !external {

		if local_pref == 0 {
			local_pref = 100
		}

		// (Well-known, Transitive, Complete, Regular length), LOCAL_PREF(5), 4 bytes
		attr := append([]byte{WTCR, LOCAL_PREF, 4}, htonl(local_pref)...)
		path_attributes = append(path_attributes, attr...)
	}

	if len(communities) > 0 {
		comms := []byte{}
		for k, v := range communities {
			if k < 60 { // should implement extended length
				c := htonl(uint32(v))
				comms = append(comms, c[:]...)
			}
		}

		// (Optional, Transitive, Complete, Regular length), COMMUNITIES(8), n bytes
		attr := append([]byte{OTCR, COMMUNITIES, uint8(len(comms))}, comms...)
		path_attributes = append(path_attributes, attr...)
	}

	if med > 0 {
		// (Optional, Non-transitive, Complete, Regular length), MULTI_EXIT_DISC(4), 4 bytes
		attr := append([]byte{ONCR, MULTI_EXIT_DISC, 4}, htonl(uint32(med))...)
		path_attributes = append(path_attributes, attr...)
	}

	//   +-----------------------------------------------------+
	//   |   Withdrawn Routes Length (2 octets)                |
	//   +-----------------------------------------------------+
	//   |   Withdrawn Routes (variable)                       |
	//   +-----------------------------------------------------+
	//   |   Total Path Attribute Length (2 octets)            |
	//   +-----------------------------------------------------+
	//   |   Path Attributes (variable)                        |
	//   +-----------------------------------------------------+
	//   |   Network Layer Reachability Information (variable) |
	//   +-----------------------------------------------------+

	var update []byte
	update = append(update, htons(uint16(len(withdrawn)))...)
	update = append(update, withdrawn...)

	if len(advertise) > 0 {
		update = append(update, htons(uint16(len(path_attributes)))...)
		update = append(update, path_attributes...)
		update = append(update, advertise...)
	} else {
		update = append(update, 0, 0) // total path attribute length 0 as there is no nlri
	}

	return update
}
