package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestReadPasswordStdin(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no line ending", "secret", "secret"},
		{"unix line ending", "secret\n", "secret"},
		{"windows line ending", "secret\r\n", "secret"},
		{"only the last line ending is trimmed", "secret\nextra\n", "secret\nextra"},
		{"empty input", "", ""},
		{"password that is a newline", "\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPasswordStdin(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("readPasswordStdin: %v", err)
			}
			if got != tc.want {
				t.Fatalf("readPasswordStdin(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestReadPasswordStdinPropagatesErrors(t *testing.T) {
	want := errors.New("stdin failed")
	if _, err := readPasswordStdin(errorReader{err: want}); !errors.Is(err, want) {
		t.Fatalf("readPasswordStdin error = %v, want %v", err, want)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }
