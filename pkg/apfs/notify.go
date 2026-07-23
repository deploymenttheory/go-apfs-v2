// Notification functions
// Corresponds to libfsapfs_notify.c and libfsapfs_notify.h
package apfs

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Notification system state
var (
	// notifyVerbose controls whether verbose notifications are enabled
	notifyVerbose bool

	// notifyStream is the output stream for notifications
	notifyStream io.Writer = os.Stderr

	// notifyFile is the file handle if stream was opened from a filename
	notifyFile *os.File

	// notifyMutex protects concurrent access to notification settings
	notifyMutex sync.RWMutex
)

// SetVerbose sets the verbose notification level
// Corresponds to libfsapfs_notify_set_verbose
// This controls all debug output in the library
func SetVerbose(verbose bool) {
	notifyMutex.Lock()
	defer notifyMutex.Unlock()

	notifyVerbose = verbose
}

// GetVerbose returns the current verbose notification level
func GetVerbose() bool {
	notifyMutex.RLock()
	defer notifyMutex.RUnlock()

	return notifyVerbose
}

// SetStream sets the notification output stream
// Corresponds to libfsapfs_notify_set_stream
func SetStream(stream io.Writer) error {
	if stream == nil {
		return fmt.Errorf("invalid stream")
	}

	notifyMutex.Lock()
	defer notifyMutex.Unlock()

	notifyStream = stream

	return nil
}

// GetStream returns the current notification output stream
func GetStream() io.Writer {
	notifyMutex.RLock()
	defer notifyMutex.RUnlock()

	return notifyStream
}

// OpenStream opens a notification stream using a filename
// The stream is opened in append mode
// Corresponds to libfsapfs_notify_stream_open
func OpenStream(filename string) error {
	if filename == "" {
		return fmt.Errorf("invalid filename")
	}

	notifyMutex.Lock()
	defer notifyMutex.Unlock()

	// Close any existing file stream
	if notifyFile != nil {
		notifyFile.Close()
		notifyFile = nil
	}

	// Open file in append mode
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to open stream: %w", err)
	}

	notifyFile = file
	notifyStream = file

	return nil
}

// CloseStream closes the notification stream if opened using a filename
// Corresponds to libfsapfs_notify_stream_close
func CloseStream() error {
	notifyMutex.Lock()
	defer notifyMutex.Unlock()

	if notifyFile != nil {
		err := notifyFile.Close()
		notifyFile = nil
		notifyStream = os.Stderr // Reset to default

		if err != nil {
			return fmt.Errorf("unable to close stream: %w", err)
		}
	}

	return nil
}

// Printf writes a formatted notification message to the notification stream
// This function is thread-safe and respects the verbose setting
// Corresponds to libcnotify_printf
func Printf(format string, args ...interface{}) {
	notifyMutex.RLock()
	verbose := notifyVerbose
	stream := notifyStream
	notifyMutex.RUnlock()

	if !verbose && !DebugOutput {
		return
	}

	fmt.Fprintf(stream, format, args...)
}

// Println writes a notification message with a newline to the notification stream
// This function is thread-safe and respects the verbose setting
func Println(args ...interface{}) {
	notifyMutex.RLock()
	verbose := notifyVerbose
	stream := notifyStream
	notifyMutex.RUnlock()

	if !verbose && !DebugOutput {
		return
	}

	fmt.Fprintln(stream, args...)
}

// Print writes a notification message to the notification stream
// This function is thread-safe and respects the verbose setting
func Print(args ...interface{}) {
	notifyMutex.RLock()
	verbose := notifyVerbose
	stream := notifyStream
	notifyMutex.RUnlock()

	if !verbose && !DebugOutput {
		return
	}

	fmt.Fprint(stream, args...)
}

// IsVerbose checks if verbose mode or debug output is enabled
// This mimics the libcnotify_verbose != 0 check in C code
func IsVerbose() bool {
	notifyMutex.RLock()
	verbose := notifyVerbose
	notifyMutex.RUnlock()

	return verbose || DebugOutput
}
