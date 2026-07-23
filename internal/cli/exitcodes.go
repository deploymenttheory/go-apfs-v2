// Exit code contract for pipeline use.
package cli

import "fmt"

// Exit codes. Stable interface for scripts and pipelines.
const (
	ExitOK           = 0 // success
	ExitError        = 1 // generic runtime error
	ExitUsage        = 2 // bad flags or arguments
	ExitBadImage     = 3 // image not found or not a recognizable APFS image
	ExitAuth         = 4 // authentication required or failed
	ExitUnsupported  = 5 // feature not supported on this platform
	ExitPartial      = 6 // operation completed partially (e.g. some files skipped)
)

// codedError carries an exit code with an error.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// withCode wraps an error with an exit code.
func withCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

// usageErrorf returns a usage error (exit 2).
func usageErrorf(format string, args ...any) error {
	return withCode(ExitUsage, fmt.Errorf(format, args...))
}

// exitCodeFor extracts the exit code from an error (default 1).
func exitCodeFor(err error) int {
	if err == nil {
		return ExitOK
	}
	for e := err; e != nil; {
		if coded, ok := e.(*codedError); ok {
			return coded.code
		}
		unwrapper, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = unwrapper.Unwrap()
	}
	return ExitError
}
