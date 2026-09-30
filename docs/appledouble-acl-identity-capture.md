# Source ACL identity capture

Darwin ACL text can refer to account names and numeric user or group IDs. Those
identities belong to the source directory service. Looking up an identically
named Linux or Windows account does not reproduce that source mapping.

`hostmeta.NewNativeACLIdentityCapture(ctx)` provides explicit source acquisition
on macOS through pure Go libSystem bindings. Its `Resolve` and `Lookup` methods
record successful observations in both directions, including confirmed absence.
Persist `Snapshot()` with the source metadata. `Snapshot.Resolvers()` validates
the captured records and supplies immutable callbacks for parsing and formatting
the same ACL on Linux, Windows and macOS. Uncaptured queries remain explicit
errors; forward observations cannot safely be inverted to invent reverse ones.

The native constructor is a macOS acquisition boundary. Linux and Windows use
the same portable captured resolver and ACL codec; they do not substitute their
host account database. Explicit UUID ACL entries require no name lookup.

The default per-record buffer limit is 16 MiB. The `WithLimit` constructor allows
a different positive bound. Buffer exhaustion returns `ErrACLIdentityLimit`,
not an absent account. Context cancellation is checked between calls; an
in-progress native directory-service call cannot be interrupted. Capture is
sequential; validated snapshot resolvers support concurrent replay. Only account
name, ID, group distinction and UUID enter the snapshot. Passwords, home
directories, descriptions and membership lists are never read into it.

## Qualification and evidence

`go run scripts/verify-acl-identity-capture-native.go` compares the provider with
an independent C observer built against the installed SDK. It covers fixed
system identities, absent names and IDs, an unknown UUID and the running
process's identity. Current-user observations remain in process memory. The
published report contains comparison counts, source hashes, compiler, SDK and
host versions, plus both arm64 and x86_64 AST hashes. It omits account records
and query arguments. AST layout assertions cover `passwd` and `group`; executing
on one architecture does not establish execution on the other.

The retained `testdata/appledouble/native/acl-identity-capture.json.gz` contains
only fixed public system identities and fixed negative cases. Every OS replays
that snapshot, checks the C observer hashes and rejects unexpected account names
or numeric IDs in the fixture. Production snapshots can contain private source
identity mappings and belong to their caller, not qualification artifacts.

`scripts/verify-metadata-transport-coverage.go` requires greater than 95% coverage
for each new provider file, checks skipped tests and retains raw coverage and
test events. Tests exercise cancellation, buffer growth and limits, native
failures, malformed pointers, absent accounts, forward and reverse queries and
portable replay. These component checks do not replace the complete transport
matrix or final Linux, Windows and macOS CI qualification.
