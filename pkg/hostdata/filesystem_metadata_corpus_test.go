package hostdata

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type filesystemMetadataCorpus struct {
	Name, Path, Profile string
	Cases               int
}

func filesystemMetadataCorpora() []filesystemMetadataCorpus {
	fresh := os.Getenv("APFS_METADATA_FILESYSTEM_PRODUCERS")
	var result []filesystemMetadataCorpus
	for _, major := range []int{15, 26, 27} {
		for _, packed := range []bool{false, true} {
			// The retained packed corpus was executed on 27. Fresh CI requires all
			// three actual producers; never label a 27 observation as an older host.
			if packed && major != 27 && fresh == "" {
				continue
			}
			name, profile, cases := fmt.Sprint(major), "", 960
			path := fmt.Sprintf("../../testdata/appledouble/native/metadata-filesystem-macos%d.json.gz", major)
			if packed {
				name, profile, cases = fmt.Sprintf("packed-empty-%d", major), "packed-empty", 96
				path = fmt.Sprintf("../../testdata/appledouble/native/metadata-filesystem-packed-empty-macos%d.json.gz", major)
			}
			if fresh != "" {
				path = filepath.Join(fresh, fmt.Sprintf("filesystem-metadata-macos%d", major), "native.json")
				if packed {
					path = filepath.Join(filepath.Dir(path), "packed", "native.json")
				}
			}
			result = append(result, filesystemMetadataCorpus{name, path, profile, cases})
		}
	}
	return result
}

func TestFilesystemMetadataCorpusInventory(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(fmt.Sprint(fresh), func(t *testing.T) {
			directory := ""
			expected := 4
			if fresh {
				directory = t.TempDir()
				expected = 6
			}
			t.Setenv("APFS_METADATA_FILESYSTEM_PRODUCERS", directory)
			corpus := filesystemMetadataCorpora()
			if len(corpus) != expected {
				t.Fatal("lost native input profile", len(corpus), expected)
			}
			seen := map[string]bool{}
			for _, entry := range corpus {
				if seen[entry.Name] || entry.Path == "" {
					t.Fatal("duplicate or missing source", entry)
				}
				seen[entry.Name] = true
				if fresh {
					relative, err := filepath.Rel(directory, entry.Path)
					if err != nil || !filepath.IsLocal(relative) {
						t.Fatal("producer path escaped evidence root", entry, err)
					}
				}
			}
		})
	}
}
