package appledouble

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNativeQuarantine(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/quarantine.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Records []struct {
			Name              string
			Input, Serialized []byte
			Accepted          bool
		}
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Records) != 434 {
		t.Fatal("missing native cases", len(f.Records))
	}
	for _, tc := range f.Records {
		t.Run(tc.Name, func(t *testing.T) {
			q, err := ParseQuarantine(tc.Input)
			if (err == nil) != tc.Accepted {
				t.Fatalf("native accepted=%t, Go=%v", tc.Accepted, err)
			}
			if err != nil {
				return
			}
			b, err := q.MarshalBinary()
			if err != nil || !bytes.Equal(b, tc.Serialized) {
				t.Fatalf("got %q, want %q: %v", b, tc.Serialized, err)
			}
		})
	}
}

func TestQuarantineModelBounds(t *testing.T) {
	for _, q := range []*Quarantine{nil, {Flags: 0x4000}, {Agent: string(make([]byte, 256))}, {Identifier: string(make([]byte, 65))}, {Agent: "a\x00b"}, {Identifier: "a\x00b"}} {
		if _, err := q.MarshalBinary(); !errors.Is(err, ErrQuarantine) {
			t.Fatal(q, err)
		}
	}
	q := &Quarantine{}
	b, err := q.MarshalBinary()
	if err != nil || string(b) != "q/0001;00000000;;\x00" {
		t.Fatal(string(b), err)
	}
	q = &Quarantine{Flags: 0x3fff, Timestamp: ^uint32(0), Agent: strings.Repeat("\xff", 255), Identifier: strings.Repeat("\xfe", 64)}
	b, err = q.MarshalBinary()
	if err != nil || len(b) != 1294 {
		t.Fatal(len(b), err)
	}
	decoded, err := ParseQuarantine(b)
	if err != nil || *decoded != *q {
		t.Fatal(decoded, err)
	}
	b[2] = '0'
	if decoded.Flags != 0x3fff {
		t.Fatal("parsed result aliases input")
	}
	// Generic byte decoding must retain rejected policy records for inspection.
	raw, err := FromXattrs(map[string][]byte{QuarantineName: []byte("INVALID")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	f, err := Decode(raw)
	if err != nil || string(f.Xattrs()[QuarantineName]) != "INVALID" {
		t.Fatal(f, err)
	}
}
func FuzzQuarantine(f *testing.F) {
	for _, s := range []string{"q/0081;12345678;Probe;ID\x00", "q/81;1", "q/81;1;a\\x00b;", "q/81;1;a\\x5c;ID"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		q, err := ParseQuarantine(b)
		if err != nil {
			return
		}
		encoded, err := q.MarshalBinary()
		if err != nil || len(encoded) > 1294 {
			t.Fatal(len(encoded), err)
		}
		again, err := ParseQuarantine(encoded)
		if err != nil || *again != *q {
			t.Fatal(again, q, err)
		}
		stable, err := again.MarshalBinary()
		if err != nil || !bytes.Equal(encoded, stable) {
			t.Fatal("unstable canonicalization", err)
		}
	})
}
