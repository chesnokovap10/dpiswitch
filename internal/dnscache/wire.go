package dnscache

import (
	"encoding/binary"
)

// Just enough of the DNS message format for a cache: a query's question,
// the TTLs of an answer's records, and an answer made out of a kept one.

const (
	typeSOA = 6
	typeOPT = 41

	rcodeOK       = 0
	rcodeFormErr  = 1
	rcodeServFail = 2
	rcodeNXDomain = 3
	rcodeNotImp   = 4
)

// question: the key a query's question is kept under -- its name in lower
// case with type and class, as they stand in the message -- and where the
// question ends. ok is false for anything but a query of one question.
func question(m []byte) (key string, end int, ok bool) {
	if len(m) < 12 || m[2]&0x80 != 0 || binary.BigEndian.Uint16(m[4:]) != 1 {
		return "", 0, false
	}
	off := 12
	for {
		if off >= len(m) {
			return "", 0, false
		}
		l := int(m[off])
		if l == 0 {
			off++
			break
		}
		// a question's name is never compressed: there is nothing before it
		if l&0xc0 != 0 || off+1+l > len(m) {
			return "", 0, false
		}
		off += 1 + l
	}
	if off+4 > len(m) {
		return "", 0, false
	}
	end = off + 4
	k := make([]byte, end-12)
	copy(k, m[12:end])
	for i, c := range k {
		if 'A' <= c && c <= 'Z' {
			k[i] = c + 'a' - 'A'
		}
	}
	return string(k), end, true
}

func skipName(m []byte, off int) (int, bool) {
	for off < len(m) {
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xc0 == 0xc0: // a pointer: two bytes, and the name ends
			return off + 2, off+2 <= len(m)
		case l&0xc0 != 0:
			return off, false
		default:
			off += 1 + l
		}
	}
	return off, false
}

// records calls f for every record past the question -- its section (0
// answer, 1 authority, 2 additional), type, and offsets of its TTL and data;
// false for a message that does not parse to its end
func records(m []byte, f func(sec int, typ uint16, ttlOff int, rdata []byte)) bool {
	if len(m) < 12 {
		return false
	}
	off := 12
	for i := 0; i < int(binary.BigEndian.Uint16(m[4:])); i++ {
		var ok bool
		if off, ok = skipName(m, off); !ok || off+4 > len(m) {
			return false
		}
		off += 4
	}
	for sec := 0; sec < 3; sec++ {
		n := int(binary.BigEndian.Uint16(m[6+2*sec:]))
		for i := 0; i < n; i++ {
			var ok bool
			if off, ok = skipName(m, off); !ok || off+10 > len(m) {
				return false
			}
			typ := binary.BigEndian.Uint16(m[off:])
			rdl := int(binary.BigEndian.Uint16(m[off+8:]))
			if off+10+rdl > len(m) {
				return false
			}
			f(sec, typ, off+4, m[off+10:off+10+rdl])
			off += 10 + rdl
		}
	}
	return true
}

// negativeTTL: how long a "no such name" or "no such record" with no SOA to
// say is kept
const negativeTTL = 60

// keepable: whether an answer is kept, and its TTL -- the smallest of its
// answer records; for a name or record that does not exist, the SOA's
// (RFC 2308). A failure is not kept: a server failing now says nothing of
// the name, and the answer kept before is better than none.
func keepable(m []byte) (uint32, bool) {
	if len(m) < 12 || m[2]&0x80 == 0 || m[2]&0x02 != 0 {
		return 0, false // not an answer, or truncated
	}
	rc := m[3] & 0x0f
	if rc != rcodeOK && rc != rcodeNXDomain {
		return 0, false
	}
	ttl, have := uint32(0), false
	neg, haveNeg := uint32(0), false
	ok := records(m, func(sec int, typ uint16, ttlOff int, rdata []byte) {
		t := binary.BigEndian.Uint32(m[ttlOff:])
		switch {
		case sec == 0 && typ != typeOPT:
			if !have || t < ttl {
				ttl, have = t, true
			}
		case sec == 1 && typ == typeSOA && len(rdata) >= 4:
			// the smaller of the record's TTL and its MINIMUM, the last field
			if min := binary.BigEndian.Uint32(rdata[len(rdata)-4:]); min < t {
				t = min
			}
			if !haveNeg || t < neg {
				neg, haveNeg = t, true
			}
		}
	})
	if !ok {
		return 0, false
	}
	switch {
	case have && rc == rcodeOK:
		return ttl, true
	case haveNeg:
		return neg, true
	}
	return negativeTTL, true
}

// withTTLs: m with every record's TTL replaced by ttl(old one); OPT's TTL
// is its flags and is left alone
func withTTLs(m []byte, ttl func(uint32) uint32) {
	records(m, func(_ int, typ uint16, ttlOff int, _ []byte) {
		if typ != typeOPT {
			binary.BigEndian.PutUint32(m[ttlOff:], ttl(binary.BigEndian.Uint32(m[ttlOff:])))
		}
	})
}

// reply: the answer to the query q made out of the kept one -- the query's
// ID, its recursion-desired bit and its question as it was written (the
// same length: the name differs in case at most), and the TTLs given by ttl
func reply(q []byte, qend int, kept []byte, ttl func(uint32) uint32) []byte {
	out := append([]byte(nil), kept...)
	copy(out[:2], q[:2])
	out[2] = out[2]&^0x01 | q[2]&0x01
	copy(out[12:qend], q[12:qend])
	withTTLs(out, ttl)
	return out
}

// failure: an answer to q with no records and the rcode given
func failure(q []byte, qend int, rcode byte) []byte {
	if qend < 12 || qend > len(q) {
		qend = 12
	}
	out := make([]byte, qend)
	copy(out, q[:qend])
	out[2] = 0x80 | q[2]&0x79 // a response; the opcode and RD as asked
	out[3] = 0x80 | rcode     // recursion available
	qd := uint16(0)
	if qend > 12 {
		qd = 1
	}
	binary.BigEndian.PutUint16(out[4:], qd)
	clear(out[6:12])
	return out
}

// truncate: the answer cut to its header and question, with TC set -- the
// asker comes again over TCP
func truncate(resp []byte, qend int) []byte {
	out := append([]byte(nil), resp[:qend]...)
	out[2] |= 0x02
	clear(out[6:12])
	return out
}
