// Name normalization.
//
// HFS+ stores names decomposed, so a name given with a precomposed character
// such as "ü" (U+00FC) is stored as "u" followed by a combining diaeresis. A
// writer that stores the precomposed form produces a name macOS will not find,
// because it looks for the decomposed one.
//
// The decomposition is NFD with an exclusion list; see normalize_table.go for
// what is excluded and how that was established.
package hfsplus

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// shouldDecompose reports whether a rune takes part in decomposition.
func shouldDecompose(r rune) bool {
	for _, span := range noDecompose {
		if r >= span[0] && r <= span[1] {
			return false
		}
	}
	return true
}

// normalizeName returns the form HFS+ stores a name in.
//
// Decomposition is applied per rune rather than to the string as a whole,
// because the exclusion list is per rune: running NFD over the whole string
// would decompose the excluded ones along with everything else.
func normalizeName(name string) string {
	// Almost every name is already in this form, and rewriting one that is
	// costs an allocation for nothing.
	if !needsNormalizing(name) {
		return name
	}

	var b strings.Builder
	b.Grow(len(name) + 8)
	for _, r := range name {
		if shouldDecompose(r) {
			b.WriteString(norm.NFD.String(string(r)))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// needsNormalizing reports whether any rune would change.
func needsNormalizing(name string) bool {
	for _, r := range name {
		if r < 0x00C0 {
			// Nothing below Latin-1 Supplement decomposes, which covers the
			// overwhelming majority of names.
			continue
		}
		if !shouldDecompose(r) {
			continue
		}
		if s := string(r); norm.NFD.String(s) != s {
			return true
		}
	}
	return false
}
