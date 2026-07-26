// Notification functions
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

// setVerbose sets the verbose notification level
// This controls all debug output in the library
func setVerbose(verbose bool) {
	notifyMutex.Lock()
	defer notifyMutex.Unlock()

	notifyVerbose = verbose
}

// verbose returns the current verbose notification level
func verbose() bool {
	notifyMutex.RLock()
	defer notifyMutex.RUnlock()

	return notifyVerbose
}

// setStream sets the notification output stream
func setStream(stream io.Writer) error {
	if stream == nil {
		return fmt.Errorf("invalid stream")
	}

	notifyMutex.Lock()
	defer notifyMutex.Unlock()

	notifyStream = stream

	return nil
}

// stream returns the current notification output stream
func stream() io.Writer {
	notifyMutex.RLock()
	defer notifyMutex.RUnlock()

	return notifyStream
}

// openStream opens a notification stream using a filename
// The stream is opened in append mode
func openStream(filename string) error {
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

// closeStream closes the notification stream if opened using a filename
func closeStream() error {
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

// printf writes a formatted notification message to the notification stream
// This function is thread-safe and respects the verbose setting
func notifyPrintf(format string, args ...interface{}) {
	notifyMutex.RLock()
	verbose := notifyVerbose
	stream := notifyStream
	notifyMutex.RUnlock()

	if !verbose && !DebugOutput {
		return
	}

	fmt.Fprintf(stream, format, args...)
}

// println writes a notification message with a newline to the notification stream
// This function is thread-safe and respects the verbose setting
func notifyPrintln(args ...interface{}) {
	notifyMutex.RLock()
	verbose := notifyVerbose
	stream := notifyStream
	notifyMutex.RUnlock()

	if !verbose && !DebugOutput {
		return
	}

	fmt.Fprintln(stream, args...)
}

// print writes a notification message to the notification stream
// This function is thread-safe and respects the verbose setting
func notifyPrint(args ...interface{}) {
	notifyMutex.RLock()
	verbose := notifyVerbose
	stream := notifyStream
	notifyMutex.RUnlock()

	if !verbose && !DebugOutput {
		return
	}

	fmt.Fprint(stream, args...)
}

// isVerbose checks if verbose mode or debug output is enabled
// Reports whether verbose debug output is enabled.
func isVerbose() bool {
	notifyMutex.RLock()
	verbose := notifyVerbose
	notifyMutex.RUnlock()

	return verbose || DebugOutput
}
