package lzbitmap

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand/v2"
	"testing"
	"time"
)

// TestIncompressibleIsNotQuadratic guards the encoder's worst case. The
// pattern search sweeps up to 64 KiB of history for every eight bytes, so
// input it can never match once cost about 8000 comparisons a byte: a
// first cut of this package managed 0.2 MB/s on random data, which would
// have taken about twenty minutes over a 300 MB payload and produced
// nothing smaller. The bound is loose enough for a slow shared runner and
// still an order of magnitude under that.
func TestIncompressibleIsNotQuadratic(t *testing.T) {
	limit := 20 * time.Second
	// Atomic statement counters instrument the byte-search inner loops, just
	// as the race detector does. Ordinary test runs retain the 20-second
	// throughput guard; instrumented runs execute the same complete workload.
	if raceEnabled || testing.CoverMode() == "atomic" {
		limit = 3 * time.Minute
	}
	buf := make([]byte, 8<<20)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, err := Compress(buf)
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	if took > limit {
		t.Errorf("compressing 8 MiB of random data took %s", took.Round(time.Millisecond))
	}
	// It should also give up rather than bloat: the chunks get stored.
	if len(out) > len(buf)+len(buf)/64 {
		t.Errorf("random input grew from %d to %d bytes", len(buf), len(out))
	}
	t.Logf("8 MiB of random data in %s (%.1f MB/s), %d bytes out",
		took.Round(time.Millisecond), float64(len(buf))/took.Seconds()/1e6, len(out))
}

// This checks the adaptive search budget without relying on runner speed. A
// regression that keeps scanning the full history on unproductive input must
// fail even when a coverage or race build has a larger elapsed-time allowance.
func TestIncompressibleSearchBackoff(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(1, 2))
	input := make([]byte, MaxChunk)
	for i := range input {
		input[i] = byte(random.Uint32())
	}
	e := encoder{src: input, pos: 8, decmpLen: len(input), period: initialPeriod}
	groups, wide := 0, 0
	for e.pos < len(input) {
		if !e.cheap || e.probe == 0 {
			wide++
		}
		e.eightBytes()
		groups++
	}
	// At least seven of every eight random groups must avoid the wide
	// history scan. The margin includes initial sampling and later probes.
	if wide*8 >= groups {
		t.Fatalf("unproductive wide searches: %d of %d groups", wide, groups)
	}
	t.Logf("wide searches: %d of %d incompressible groups", wide, groups)
}

func BenchmarkCompress(b *testing.B) {
	random := make([]byte, 1<<20)
	rand.Read(random)
	text := make([]byte, 0, 1<<20)
	for len(text) < 1<<20 {
		text = append(text, []byte("package payload contents, fairly repetitive text 0123456789\n")...)
	}
	text = text[:1<<20]
	for _, c := range []struct {
		name string
		in   []byte
	}{{"random", random}, {"text", text}} {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(c.in)))
			for i := 0; i < b.N; i++ {
				if _, err := Compress(c.in); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecompress(b *testing.B) {
	in := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), 2000)
	enc, err := Compress(in)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decompress(enc); err != nil {
			b.Fatal(err)
		}
	}
}
