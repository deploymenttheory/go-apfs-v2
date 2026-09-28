package appledouble

import (
	"errors"
	"fmt"
	"strings"
)

// ErrQuarantineContext means process state is unavailable or outside the
// independently qualified application contexts. It must not imply no quarantine.
var ErrQuarantineContext = errors.New("appledouble: unqualified quarantine process context")

// ErrQuarantineApplicationSize identifies the native application buffer limit.
// An envelope can be valid for serialization yet too large for application.
var ErrQuarantineApplicationSize = errors.New("appledouble: quarantine application value exceeds buffer")

// ErrQuarantineMissing identifies application that requires an existing
// quarantine attribute but finds none (the qualified native ENOATTR outcome).
var ErrQuarantineMissing = errors.New("appledouble: quarantine application requires an existing attribute")

// MaxQuarantineApplicationSize is the largest canonical plain value accepted
// before native application. This is distinct from MaxQuarantineXattrSize.
const MaxQuarantineApplicationSize = 381

// QuarantineProcess supplies known effective flags and the raw kernel agent.
// Agent is byte data, not an escaped field. Native process snapshots can lose
// backslash bytes; callers must resolve the raw agent independently when that
// happens. Requested flags cannot substitute for captured effective flags, and
// a refused process change cannot supply either field.
type QuarantineProcess struct {
	Flags uint32
	Agent string
}

// QuarantineApplicationContext supplies policy inputs independently of the Go
// host. Process must be known; nil is unavailable, not unquarantined. Qualified
// process flags are 0x001 through 0x01f for macOS 26 and 0x200 through 0x21f for macOS
// 27. Other contexts require further native qualification.
//
// Existing describes the actual prepared destination, after cleanup or baseline
// writes; nil means confirmed attribute absence. Timestamp is an injected Unix
// time in seconds, used when policy refreshes a regular file's timestamp.
// Directory selects the qualified directory behavior; links and other object
// kinds have not been qualified. This type grants no filesystem permission.
type QuarantineApplicationContext struct {
	Profile   QuarantineProfile
	Process   *QuarantineProcess
	Existing  *Quarantine
	Directory bool
	Timestamp uint32
}

// QuarantineApplication requests either an exact xattr write or preservation.
// With Write false, preserve the original raw attribute (including absence);
// Value is nil. Value with Write true is the exact plain filesystem value, not
// an AppleDouble envelope and not necessarily a canonical serialized model.
// Kernel agent insertion and identifier truncation can change its interpretation.
type QuarantineApplication struct {
	Write bool
	Value []byte
}

// PlanApplication reproduces qualified direct quarantine application policy in
// pure Go. It does not access a filesystem, capture process state, read the clock,
// or perform copyfile's preceding cleanup. Feed valid ordered QuarantineUpdates
// through this operation using the destination state at each record's position.
//
// Errors do not request a write. Invalid source/existing models or profiles return
// ErrQuarantine. Unknown process context, application size and missing-attribute
// outcomes have distinct sentinel errors. Actual transport permission/I/O errors
// and copyfile callback decisions still belong to the caller.
func (q *Quarantine) PlanApplication(ctx QuarantineApplicationContext) (*QuarantineApplication, error) {
	envelope, err := q.MarshalBinaryWithProfile(ctx.Profile)
	if err != nil {
		return nil, err
	}
	if ctx.Existing != nil {
		if _, err := ctx.Existing.MarshalBinaryWithProfile(ctx.Profile); err != nil {
			return nil, err
		}
	}
	if !qualifiedQuarantineProcess(ctx.Profile, ctx.Process) {
		return nil, ErrQuarantineContext
	}
	raw := envelope[2 : len(envelope)-1]
	if len(raw) > MaxQuarantineApplicationSize {
		return nil, ErrQuarantineApplicationSize
	}
	flags := q.Flags
	if flags == 0 {
		flags = 1
	}
	sandbox := ctx.Process.Flags&2 != 0
	if sandbox {
		flags &^= 0x60
		if ctx.Existing != nil {
			flags |= ctx.Existing.Flags & 6
		}
		if flags == 0 {
			// This native fallback keeps the input's encoded fields and timestamp,
			// including the full identifier, rather than performing kernel substitution.
			copy(raw[:4], "0081")
			return &QuarantineApplication{Write: true, Value: raw}, nil
		}
	}
	if ctx.Process.Flags&0x200 != 0 {
		flags &^= 0x218
	}
	if flags == 0 {
		if sandbox && ctx.Existing == nil {
			return nil, ErrQuarantineMissing
		}
		return &QuarantineApplication{}, nil
	}
	if flags&3 != 0 && flags&0x40 == 0 {
		flags |= 0x80
	}
	timestamp := ctx.Timestamp
	if ctx.Directory {
		timestamp = 0
	}
	value := fmt.Appendf(nil, "%04x;%08x;", flags, timestamp)
	value = append(value, ctx.Process.Agent...)
	value = append(value, ';')
	identifier := escapeQuarantine(nil, q.Identifier)
	// Native truncates encoded bytes, even partway through a four-byte escape.
	value = append(value, identifier[:min(len(identifier), 63)]...)
	return &QuarantineApplication{Write: true, Value: value}, nil
}

func qualifiedQuarantineProcess(profile QuarantineProfile, p *QuarantineProcess) bool {
	if p == nil || len(p.Agent) > 255 || strings.IndexByte(p.Agent, 0) >= 0 {
		return false
	}
	switch profile {
	case QuarantineMacOS26:
		return p.Flags >= 1 && p.Flags <= 0x1f
	case QuarantineMacOS27:
		return p.Flags >= 0x200 && p.Flags <= 0x21f
	default:
		return false
	}
}
