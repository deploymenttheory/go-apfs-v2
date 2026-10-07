//go:build ignore

package main

import (
	"fmt"
	"testing"
)

func TestAdmissionProfileProvenance(t *testing.T) {
	for _, actual := range []int{15, 26, 27} {
		for _, expected := range []int{15, 26, 27} {
			err := requireAdmissionProfile(fmt.Sprintf("ProductVersion: %d.1\nBuildVersion: native", actual), expected)
			if (err == nil) != (actual == expected) {
				t.Fatalf("actual%d expected%d error=%v", actual, expected, err)
			}
		}
	}
	for _, host := range []string{"", "ProductVersion: 14.0", "ProductVersion: invalid"} {
		if requireAdmissionProfile(host, 27) == nil {
			t.Fatalf("accepted invalid native source %q", host)
		}
	}
}
