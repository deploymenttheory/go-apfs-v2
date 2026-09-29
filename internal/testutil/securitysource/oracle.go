// Package securitysource shares native source-acquisition evidence and replay.
// It is test support, not a native host adapter.
package securitysource

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

type Event struct {
	securitycopy.Event
	Source *securitycopy.Source
	Stat   *hostmeta.SecuritySourceStat
}
type Observation struct {
	PayloadPermissionCleanups                int
	Events                                   []Event
	Code, Errno, CopyCode                    int
	Entered                                  bool
	Cache                                    securitycopy.Properties
	FinalSource                              securitycopy.Source
	SourceBefore, SourceAfter, Before, After securitycopy.Metadata
	IdentityUnchanged, PayloadUnchanged      bool
}
type Case struct {
	Name, Kind, SourceACL, DestinationACL      string
	Flags, Presence, SourceError, StatBehavior int
	Mode                                       uint32
	Native                                     Observation
}
type Fixture struct {
	Revision, Host, HelperSHA256, ParentSHA256, CopyfileSHA256, LibcSHA256 string
	Models, Applications                                                   []Case
}

func source(v securitycopy.Source) (hostmeta.SecurityCopySource, error) {
	p, e := v.Properties.Go()
	return hostmeta.SecurityCopySource{Properties: p, UID: v.UID, GID: v.GID, Mode: v.Mode}, e
}
func sourceFromGo(v hostmeta.SecurityCopySource) securitycopy.Source {
	return securitycopy.Source{Properties: securitycopy.PropertiesFromGo(v.Properties), UID: v.UID, GID: v.GID, Mode: v.Mode}
}
func readError(e Event) error {
	if e.Code == 0 {
		return nil
	}
	native := securitycopy.NativeError(e.Errno)
	if e.Operation == "read-security" {
		if e.Errno == 1 {
			return errors.Join(native, hostmeta.ErrSecuritySourceNotPermitted)
		}
		if e.Errno == 45 {
			return errors.Join(native, hostmeta.ErrSecuritySourceNotSupported)
		}
	}
	return native
}

// Replay compares captured partial state, fallback diagnostics, source type
// gating and the ordinary copy's exact requests/cache with the native trace.
func Replay(tc Case) (hostmeta.SecuritySourceCopyResult, []securitycopy.Event, error) {
	n := tc.Native
	var reads []Event
	var acquired securitycopy.Source
	var copyEvents []securitycopy.Event
	for _, e := range n.Events {
		switch e.Operation {
		case "read-security", "read-stat":
			reads = append(reads, e)
		case "acquired":
			if e.Source == nil {
				return hostmeta.SecuritySourceCopyResult{}, nil, fmt.Errorf("missing acquisition snapshot")
			}
			acquired = *e.Source
		default:
			copyEvents = append(copyEvents, e.Event)
		}
	}
	index := 0
	next := func(op string) (Event, error) {
		if index >= len(reads) || reads[index].Operation != op {
			return Event{}, fmt.Errorf("unexpected source operation %s", op)
		}
		e := reads[index]
		index++
		return e, nil
	}
	capture := hostmeta.SecuritySourceCapture{
		ReadSecurity: func() (hostmeta.SecurityCopySource, error) {
			e, err := next("read-security")
			if err != nil {
				return hostmeta.SecurityCopySource{}, err
			}
			if e.Source == nil {
				return hostmeta.SecurityCopySource{}, fmt.Errorf("missing source")
			}
			s, err := source(*e.Source)
			if err != nil {
				return s, err
			}
			return s, readError(e)
		},
		ReadStat: func(previous hostmeta.SecuritySourceStat) (hostmeta.SecuritySourceStat, error) {
			e, err := next("read-stat")
			if err != nil {
				return previous, err
			}
			if e.Stat == nil {
				return previous, fmt.Errorf("missing stat")
			}
			first := reads[0].Source
			if previous != (hostmeta.SecuritySourceStat{UID: first.UID, GID: first.GID, Mode: first.Mode}) {
				return previous, fmt.Errorf("prior stat mismatch")
			}
			return *e.Stat, readError(e)
		},
	}
	backend := securitycopy.NewBackend(copyEvents)
	result, runErr := hostmeta.CopySecurityFrom(capture, securitycopy.Options(tc.Flags, 0), backend)
	fail := func(message string) (hostmeta.SecuritySourceCopyResult, []securitycopy.Event, error) {
		return result, backend.Events(), fmt.Errorf("%s: %s (%v)", tc.Name, message, runErr)
	}
	if index != len(reads) || backend.Mismatch() != nil || !reflect.DeepEqual(backend.Events(), copyEvents) {
		return fail("source/copy operation order")
	}
	if result.Capture.Completed != n.Entered || result.Capture.Fallback != (len(reads) == 2) {
		return fail("capture outcome")
	}
	expected := n.FinalSource
	if n.Entered {
		expected = acquired
	}
	if !reflect.DeepEqual(sourceFromGo(result.Capture.Source), expected) {
		return fail("acquired source cache")
	}
	failures := 0
	for _, e := range reads {
		if e.Code != 0 {
			if failures >= len(result.Capture.Failures) {
				return fail("missing read failure")
			}
			got := result.Capture.Failures[failures]
			op := "security"
			if e.Operation == "read-stat" {
				op = "stat"
			}
			if got.Operation != op || !errors.Is(got.Err, securitycopy.NativeError(e.Errno)) {
				return fail("read failure cause")
			}
			failures++
		}
	}
	if failures != len(result.Capture.Failures) {
		return fail("extra read failure")
	}
	if !n.Entered {
		if runErr == nil || !reflect.DeepEqual(result.Copy, hostmeta.SecurityCopyResult{}) {
			return fail("fatal capture issued copy")
		}
		if n.Errno == 45 {
			if !errors.Is(runErr, hostmeta.ErrSecuritySourceType) {
				return fail("source type refusal")
			}
		} else if !errors.Is(runErr, securitycopy.NativeError(n.Errno)) {
			return fail("fatal source cause")
		}
		return result, nil, nil
	}
	reference := securitycopy.Case{Flags: tc.Flags, Native: securitycopy.Observation{Source: acquired, Cache: n.Cache, Events: copyEvents, Code: n.CopyCode, Errno: n.Errno}}
	copied, _, err := securitycopy.Replay(reference)
	if err != nil {
		return result, backend.Events(), err
	}
	if !reflect.DeepEqual(result.Copy, copied) || (runErr != nil) != (n.CopyCode != 0) {
		return fail("integrated copy differs")
	}
	return result, backend.Events(), nil
}
