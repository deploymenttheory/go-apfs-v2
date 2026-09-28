package appledouble

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// QuarantineName identifies the serialized quarantine record in AppleDouble.
const QuarantineName = "com.apple.quarantine"

// ErrQuarantine identifies malformed or out-of-range serialized quarantine data.
var ErrQuarantine = errors.New("appledouble: invalid serialized quarantine")

// Quarantine is the logical content of libquarantine's q/ envelope. Agent and
// Identifier contain decoded bytes, which need not be UTF-8. Timestamp is the
// native 32-bit hexadecimal field. Applying this metadata can change flags,
// timestamp and agent; this type describes serialization, not host application.
type Quarantine struct {
	Flags      uint32
	Timestamp  uint32
	Agent      string
	Identifier string
}

// ParseQuarantine interprets the native serialized envelope, including numeric
// width, escape, NUL and missing-separator quirks. It does not parse the plain
// filesystem xattr form. Decode retains the raw record without calling this API.
func ParseQuarantine(data []byte) (*Quarantine, error) {
	if n := bytes.IndexByte(data, 0); n >= 0 {
		data = data[:n]
	}
	s := string(data)
	if !strings.HasPrefix(s, "q/") {
		return nil, ErrQuarantine
	}
	flags, pos, ok := quarantineHex(s, 2, 4)
	if !ok || flags > 0x3fff || pos >= len(s) || s[pos] != ';' {
		return nil, ErrQuarantine
	}
	timestamp, pos, ok := quarantineHex(s, pos+1, 8)
	if !ok {
		return nil, ErrQuarantine
	}
	// Native scanning accepts two numeric assignments even if the following
	// semicolon fails. The text-field offset then remains at the envelope start.
	text := s
	if pos < len(s) && s[pos] == ';' {
		text = s[pos+1:]
	}
	agent, id, ok := strings.Cut(text, ";")
	if !ok {
		return nil, ErrQuarantine
	}
	agent, err := unescapeQuarantine(agent, 255)
	if err != nil {
		return nil, err
	}
	id, err = unescapeQuarantine(id, 64)
	if err != nil {
		return nil, err
	}
	if flags == 0 {
		flags = 1
	}
	return &Quarantine{Flags: flags, Timestamp: timestamp, Agent: agent, Identifier: id}, nil
}

func quarantineHex(s string, pos, width int) (uint32, int, bool) {
	for pos < len(s) && strings.IndexByte(" \t\n\r\v\f", s[pos]) >= 0 {
		pos++
	}
	end := pos + min(width, len(s)-pos)
	negative := false
	if pos < end && (s[pos] == '+' || s[pos] == '-') {
		negative = s[pos] == '-'
		pos++
	}
	if pos+2 < end && s[pos] == '0' && (s[pos+1] == 'x' || s[pos+1] == 'X') && quarantineDigit(s[pos+2]) >= 0 {
		pos += 2
	}
	start := pos
	var value uint32
	for pos < end {
		n := quarantineDigit(s[pos])
		if n < 0 {
			break
		}
		value = value*16 + uint32(n)
		pos++
	}
	if negative {
		value = 0 - value
	}
	return value, pos, pos > start
}
func quarantineDigit(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	default:
		return -1
	}
}
func unescapeQuarantine(s string, limit int) (string, error) {
	b := make([]byte, 0, min(len(s), limit))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			c = '?'
			if i+3 < len(s) && s[i+1] == 'x' {
				a, z := quarantineDigit(s[i+2]), quarantineDigit(s[i+3])
				if a >= 0 && z >= 0 {
					c = byte(a*16 + z)
					i += 3
				}
			}
		}
		if len(b) == limit {
			return "", ErrQuarantine
		}
		b = append(b, c)
	}
	if n := bytes.IndexByte(b, 0); n >= 0 {
		b = b[:n]
	}
	return string(b), nil
}

// MarshalBinary emits canonical q/ data with its terminating NUL. Zero flags
// normalize to 1, as in native parsing. Model strings must fit the decoded field
// limits and contain no NUL; other bytes are escaped using native lowercase hex.
func (q *Quarantine) MarshalBinary() ([]byte, error) {
	if q == nil || q.Flags > 0x3fff || len(q.Agent) > 255 || len(q.Identifier) > 64 || strings.IndexByte(q.Agent, 0) >= 0 || strings.IndexByte(q.Identifier, 0) >= 0 {
		return nil, ErrQuarantine
	}
	flags := q.Flags
	if flags == 0 {
		flags = 1
	}
	b := fmt.Appendf(nil, "q/%04x;%08x;", flags, q.Timestamp)
	b = escapeQuarantine(b, q.Agent)
	b = append(b, ';')
	b = escapeQuarantine(b, q.Identifier)
	return append(b, 0), nil
}
func escapeQuarantine(b []byte, s string) []byte {
	const digits = "0123456789abcdef"
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 33 || c > 126 || strings.IndexByte("\"$,/:;[]\\{}", c) >= 0 {
			b = append(b, '\\', 'x', digits[c>>4], digits[c&15])
		} else {
			b = append(b, c)
		}
	}
	return b
}
