// Package pathnative describes public macOS copyfile path observations. It
// records actual filesystem effects; it does not substitute a syscall model.
package pathnative

type Snapshot struct {
	Exists               bool
	Errno                int
	Mode                 uint32
	Size                 int64
	ACLCount, XattrErrno int
	XattrHex             string
}

type Notice struct {
	What, Stage int
	Copied      int64
}
type Observation struct {
	Before, After, Source, Target                     Snapshot
	Code, Errno                                       int
	Notices                                           []Notice
	SourceOpenBeforeFree, DestinationOpenBeforeFree   bool
	SourceClosedAfterFree, DestinationClosedAfterFree bool
	FreeCode, FreeErrno                               int
	DestinationSHA256                                 string
}
type Case struct {
	Route, SourceKind, DestinationKind, Selected, Quit int
	Native                                             Observation
	SourceMode, Umask                                  int
	SetUmask                                           bool
	NullSource                                         bool
}
type Fixture struct {
	Revision, Host, HelperSHA256 string
	Cases                        []Case
}

// Cases covers pack files/directories/links and unpack valid/truncated/invalid
// source objects. Destinations include absent/file/directory/link/dangling-link.
// Selected bits: stat, exclusive, nofollow, unlink, move, ACL, retained state.
func Cases() []Case {
	var cases []Case
	for route := 0; route < 2; route++ {
		sources := 4
		if route == 1 {
			sources = 5
		}
		for source := 0; source < sources; source++ {
			for destination := 0; destination < 5; destination++ {
				for _, selected := range []int{0, 1, 2, 4, 5, 6, 12, 20, 36, 68, 69} {
					cases = append(cases, Case{Route: route, SourceKind: source, DestinationKind: destination, Selected: selected})
				}
				cases = append(cases, Case{Route: route, SourceKind: source, DestinationKind: destination, Selected: 36, Quit: 1})
			}
		}
		for _, closeFlags := range []int{0, 128, 256, 384} {
			cases = append(cases, Case{Route: route, DestinationKind: 1, Selected: 68 | closeFlags})
		}
	}
	for _, mask := range []int{0, 0077} {
		cases = append(cases, Case{Route: 1, SourceKind: 3, Selected: 4, SourceMode: 0400, Umask: mask, SetUmask: true})
	}
	for _, route := range []int{0, 1} {
		cases = append(cases, Case{Route: route, NullSource: true})
	}
	return cases
}
