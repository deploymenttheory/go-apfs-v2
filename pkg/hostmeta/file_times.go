package hostmeta

import "time"

// FileTimes contains four independently observed inode timestamps. A non-nil
// writer Entry.Times selects every field, including the Unix epoch; no field is
// inferred from another. The Go zero time is a literal year 1 value, not omission.
// This portable value describes foreign metadata, not host write authorization.
// HFS+ stores whole seconds; APFS stores nanoseconds. Writers reject explicit
// values outside their supported range rather than wrapping them.
type FileTimes struct {
	Birth, Modify, Change, Access time.Time
}
