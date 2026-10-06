//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type state struct {
	Dev, Inode            uint64
	UID, GID, Mode, Flags uint32
	Mount                 uint32 `json:"mount_flags"`
	Filesystem, Security  string
	Captured              bool `json:"security_captured"`
}
type entry struct {
	Name  string
	State state
}
type result struct {
	UID        uint32
	Groups     []uint32
	Errno      int
	Process    int `json:"process_policy"`
	ProcessErr int `json:"process_policy_errno"`
}
type record struct {
	ID, Qualification, Operation, Route string
	User                                string `json:"user_uuid"`
	Group                               string `json:"group_uuid"`
	Member                              int    `json:"group_member"`
	MemberErr                           int    `json:"group_membership_errno"`
	Before                              []entry
	Result                              result
}

func main() {
	capturePath := flag.String("capture", "", "genuine native capture path")
	flag.Parse()
	b, e := os.ReadFile(*capturePath)
	must(e)
	if strings.HasSuffix(*capturePath, ".gz") {
		z, e := gzip.NewReader(bytes.NewReader(b))
		must(e)
		b, e = io.ReadAll(z)
		must(e)
		must(z.Close())
	}
	var capture struct {
		Host        string
		Cases       []record
		Expected    int `json:"expected_cases"`
		Unavailable int `json:"unavailable_cases"`
		Failed      int `json:"failed_cases"`
	}
	must(json.Unmarshal(b, &capture))
	if capture.Expected != 318 || len(capture.Cases) != 318 || capture.Unavailable != 0 || capture.Failed != 0 {
		panic("incomplete native pathname capture")
	}
	var version osversion.Version
	for _, line := range strings.Split(capture.Host, "\n") {
		if strings.HasPrefix(line, "ProductVersion:") {
			version, e = osversion.Parse(strings.TrimSpace(strings.TrimPrefix(line, "ProductVersion:")))
			must(e)
		}
	}
	total := 0
	failed := 0
	for _, c := range capture.Cases {
		if c.Qualification != "captured" {
			panic("uncaptured case: " + c.ID)
		}
		if c.Result.ProcessErr != 0 || c.Result.Process < 0 || c.Result.Process > 1 {
			panic("uncaptured native process policy: " + c.ID)
		}
		a := authorization.Authority{UID: c.Result.UID, Groups: c.Result.Groups, Membership: map[[16]byte]authorization.Membership{}, Process: &authorization.ProcessPolicy{IgnoreNodePermissions: c.Result.Process == 1}}
		raw, e := hex.DecodeString(c.User)
		must(e)
		uuid := [16]byte(raw)
		a.UserUUID = &uuid
		raw, e = hex.DecodeString(c.Group)
		must(e)
		group := [16]byte(raw)
		if c.MemberErr != 0 {
			a.Membership[group] = authorization.MembershipFailed
		} else if c.Member != 0 {
			a.Membership[group] = authorization.Member
		} else {
			a.Membership[group] = authorization.NotMember
		}
		ev, e := authorization.New(version, &a)
		must(e)
		nodes := map[string]authorization.Node{}
		for _, entry := range c.Before {
			s := entry.State
			n := authorization.Node{Observed: true, Stat: hostdata.StatCopySource{UID: s.UID, GID: s.GID, Mode: s.Mode, Flags: s.Flags}, Identity: s.Inode, Mount: &authorization.Mount{Identity: strconv.FormatUint(s.Dev, 10), Filesystem: s.Filesystem, Flags: s.Mount}, SecurityState: authorization.SecurityAbsent}
			if s.Security != "" {
				raw, e := hex.DecodeString(s.Security)
				must(e)
				n.Security, e = appledouble.ParseFileSecurity(raw)
				must(e)
				n.SecurityState = authorization.SecurityPresent
			}
			if !s.Captured {
				panic("uncaptured native security")
			}
			nodes[entry.Name] = n
		}
		var actual error
		ctx := context.Background()
		dirs := []string{"root", "a", "a/b"}
		if c.Route == "parent" {
			dirs = []string{"a/b"}
		}
		if c.Operation != "held-write" {
			for _, d := range dirs {
				if actual = ev.Search(ctx, nodes[d]); actual != nil {
					break
				}
			}
		}
		if actual == nil {
			switch c.Operation {
			case "create":
				actual = ev.Create(ctx, nodes["a/b"], false)
			case "unlink":
				actual = ev.Delete(ctx, nodes["a/b"], nodes["a/b/file"])
			case "rename":
				dst := nodes["a/b/file"]
				actual = ev.Rename(ctx, nodes["a/b"], nodes["a/b/stage"], nodes["a/b"], &dst)
			case "rename-absent":
				actual = ev.Rename(ctx, nodes["a/b"], nodes["a/b/stage"], nodes["a/b"], nil)
			case "rename-cross":
				if actual = ev.Search(ctx, nodes["a/c"]); actual == nil {
					dst := nodes["a/c/file"]
					actual = ev.Rename(ctx, nodes["a/b"], nodes["a/b/stage"], nodes["a/c"], &dst)
				}
			}
		}
		var expected error
		switch c.Result.Errno {
		case 0:
		case 1:
			expected = syscall.EPERM
		case 13:
			expected = syscall.EACCES
		case 30:
			expected = syscall.EROFS
		default:
			panic(c.Result.Errno)
		}
		if !errors.Is(actual, expected) {
			fmt.Println("DIFFER", c.ID, actual, "native", expected)
			failed++
		}
		total++
	}
	fmt.Println("compared", total, "failed", failed)
	if failed > 0 {
		os.Exit(1)
	}
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
