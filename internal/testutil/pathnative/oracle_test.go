package pathnative

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
)

// All hosts validate the native fixture inventory, including source mode and
// process umask observations that cannot be inferred from the receiving host.
func TestPathNativeFixtureInventory(t *testing.T) {
	file, err := os.Open("../../../testdata/appledouble/native/path-copyfile.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	data, err := io.ReadAll(io.LimitReader(z, 16<<20))
	if err != nil || len(data) == 16<<20 {
		t.Fatalf("invalid or oversized native inventory: %v", err)
	}
	var fixture Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile("../../../testdata/appledouble/native/path-copyfile.c")
	if err != nil {
		t.Fatal(err)
	}
	if fixture.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(helper)) || fixture.Revision == "" || fixture.Host == "" {
		t.Fatal("native source provenance changed or absent")
	}
	generated := Cases()
	if len(fixture.Cases) != 552 || len(generated) != len(fixture.Cases) {
		t.Fatalf("incomplete inventory: native%d generated%d", len(fixture.Cases), len(generated))
	}
	for i, observed := range fixture.Cases {
		observed.Native = Observation{}
		if !reflect.DeepEqual(observed, generated[i]) {
			t.Fatalf("native input changed at case%d: %+v != %+v", i, observed, generated[i])
		}
	}
}
