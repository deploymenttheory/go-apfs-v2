// Mount path string manipulation utilities for APFS mount operations
// Corresponds to libfsapfs mount_path_string.c and mount_path_string.h
// This differs from path_string.go in that it handles filesystem path separators differently
package tools

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// Get the appropriate escape character for the platform
func getMountEscapeCharacter() rune {
	if runtime.GOOS == "windows" {
		return '^'
	}
	return '\\'
}

// Get the OS-specific path separator
func getOSPathSeparator() rune {
	return rune(filepath.Separator)
}

// EscapeMountPath escapes a file entry path for use as a mount path
// This differs from escapePath in that it:
// - Escapes the OS path separator (/ on Unix, \ on Windows)
// - On Windows, also escapes special filename characters: < > : " / | ? *
// Corresponds to mount_path_string_copy_from_file_entry_path
func EscapeMountPath(fileEntryPath string) string {
	var result strings.Builder
	result.Grow(len(fileEntryPath) * 10)

	escapeChar := getMountEscapeCharacter()
	pathSep := getOSPathSeparator()

	for _, r := range fileEntryPath {
		// Control characters (U+1-U+1f, U+7f-U+9f) and path separator
		if (r >= 0x01 && r <= 0x1f) || (r >= 0x7f && r <= 0x9f) || r == pathSep {
			result.WriteString(fmt.Sprintf("%c%c%02x", escapeChar, 'x', r))
		} else if runtime.GOOS == "windows" && shouldEscapeWindowsChar(r) {
			// Windows-specific character escaping
			result.WriteString(fmt.Sprintf("%c%c%02x", escapeChar, 'x', r))
		} else if shouldEscapeUnicode(r) {
			// Unicode escape for surrogate/undefined characters
			result.WriteString(fmt.Sprintf("%c%c%08x", escapeChar, 'U', r))
		} else if r == escapeChar {
			// Escape the escape character itself
			result.WriteRune(escapeChar)
			result.WriteRune(escapeChar)
		} else {
			// Regular character
			result.WriteRune(r)
		}
	}

	return result.String()
}

// shouldEscapeWindowsChar determines if a character needs escaping on Windows
func shouldEscapeWindowsChar(r rune) bool {
	switch r {
	case '\\', '<', '>', ':', '"', '/', '|', '?', '*':
		return true
	}
	return false
}

// UnescapeMountPath converts an escaped mount path back to a file entry path
// Corresponds to mount_path_string_copy_to_file_entry_path
func UnescapeMountPath(mountPath string) (string, error) {
	if mountPath == "" {
		return "", nil
	}

	// Path must be absolute
	if !filepath.IsAbs(mountPath) {
		return "", fmt.Errorf("path is not absolute")
	}

	var result strings.Builder
	result.Grow(len(mountPath))

	escapeChar := getMountEscapeCharacter()
	osSep := getOSPathSeparator()
	apfsSep := '/' // APFS always uses forward slash

	i := 0
	for i < len(mountPath) {
		r := rune(mountPath[i])

		// Convert OS separator to APFS separator
		if r == osSep {
			result.WriteRune(apfsSep)
			i++
			continue
		}

		if r == escapeChar {
			if i+1 >= len(mountPath) {
				return "", fmt.Errorf("incomplete escape sequence at end of path")
			}

			nextChar := rune(mountPath[i+1])
			switch nextChar {
			case escapeChar:
				// Escaped escape character
				result.WriteRune(escapeChar)
				i += 2

			case 'x', 'X':
				// \x## or ^x## -> control character or special char (2 hex digits)
				if i+3 >= len(mountPath) {
					return "", fmt.Errorf("incomplete \\x escape sequence at position %d", i)
				}
				hexValue, err := ParseHexadecimalToUint32(mountPath[i+2 : i+4])
				if err != nil {
					return "", fmt.Errorf("invalid \\x escape sequence at position %d: %w", i, err)
				}

				// Validate it's a valid escaped character
				if !isValidMountEscapedChar(hexValue) {
					return "", fmt.Errorf("invalid escaped character value 0x%02x at position %d", hexValue, i)
				}

				result.WriteRune(rune(hexValue))
				i += 4

			case 'U', 'u':
				// \U######## or ^U######## -> Unicode character (8 hex digits)
				if i+9 >= len(mountPath) {
					return "", fmt.Errorf("incomplete \\U escape sequence at position %d", i)
				}
				hexString := mountPath[i+2 : i+10]
				hexValue, err := ParseHexadecimalToUint32(hexString[:8])
				if err != nil {
					return "", fmt.Errorf("invalid \\U escape sequence at position %d: %w", i, err)
				}
				result.WriteRune(rune(hexValue))
				i += 10

			default:
				return "", fmt.Errorf("invalid escape sequence %c%c at position %d", escapeChar, nextChar, i)
			}
		} else {
			result.WriteRune(r)
			i++
		}
	}

	return result.String(), nil
}

// isValidMountEscapedChar checks if a value is valid for mount path escaping
func isValidMountEscapedChar(value uint32) bool {
	// Control characters
	if (value >= 0x01 && value <= 0x1f) || (value >= 0x7f && value <= 0x9f) {
		return true
	}

	// Path separator
	if value == uint32(getOSPathSeparator()) {
		return true
	}

	// Windows special characters
	if runtime.GOOS == "windows" {
		switch rune(value) {
		case '\\', '<', '>', ':', '"', '/', '|', '?', '*':
			return true
		}
	}

	return false
}

// ConvertMountPathToFileEntryPath converts a mount point path to an APFS file entry path
// This handles path separator conversion and path validation
func ConvertMountPathToFileEntryPath(mountPath string) (string, error) {
	// Normalize the path
	normalized := filepath.Clean(mountPath)

	// Convert to forward slashes (APFS standard)
	apfsPath := filepath.ToSlash(normalized)

	// Ensure it starts with /
	if !strings.HasPrefix(apfsPath, "/") {
		apfsPath = "/" + apfsPath
	}

	return apfsPath, nil
}

// ConvertFileEntryPathToMountPath converts an APFS file entry path to a mount point path
// This handles path separator conversion for the OS
func ConvertFileEntryPathToMountPath(fileEntryPath string) string {
	// Convert forward slashes to OS-specific separator
	return filepath.FromSlash(fileEntryPath)
}

// SanitizeMountPath removes or escapes characters that are invalid for mounting
func SanitizeMountPath(path string) string {
	// Use the escape function to ensure all special characters are handled
	return EscapeMountPath(path)
}

// ValidateMountPath checks if a mount path is valid
func ValidateMountPath(path string) error {
	if path == "" {
		return fmt.Errorf("mount path is empty")
	}

	if !filepath.IsAbs(path) {
		return fmt.Errorf("mount path must be absolute")
	}

	if strings.Contains(path, "\x00") {
		return fmt.Errorf("mount path contains null byte")
	}

	return nil
}
