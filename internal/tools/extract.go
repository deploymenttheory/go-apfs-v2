// Extract tool for extracting files from APFS volumes
// Walks the volume through its io/fs view (pkg/apfs fs.go), so extraction
// exercises the same public API that SDK consumers use.
package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/schollz/progressbar/v3"
)

// VolumeFS is the filesystem contract the extractor walks. APFS and HFS+
// volumes both implement it.
type VolumeFS interface {
	fs.FS
	fs.ReadDirFS
	fs.StatFS
	fs.ReadFileFS
	Readlink(name string) (string, error)
}

// SymlinkMode controls how symbolic links are materialized on disk.
type SymlinkMode int

const (
	// SymlinkAuto creates a real symlink where the OS permits it and falls
	// back to a regular file containing the target path otherwise (as git
	// does with core.symlinks=false). This never fails on symlink support.
	SymlinkAuto SymlinkMode = iota
	// SymlinkReal always creates a real symlink and reports a failure if the
	// OS refuses (e.g. unprivileged Windows).
	SymlinkReal
	// SymlinkFile always writes the target path into a regular file.
	SymlinkFile
)

// Extractor handles file extraction from APFS volumes
type Extractor struct {
	Volume           VolumeFS
	Destination      string
	Pattern          *regexp.Regexp
	PreserveMeta     bool
	Verbose          bool
	VerifyChecksum   bool
	SymlinkMode      SymlinkMode
	filesExtracted   int
	entriesSkipped   int
	symlinksDegraded int
	namesRemapped    int
	bytesExtracted   uint64
	sourceChecksums  map[string]string // relativePath -> SHA256 of source data
	progressBar      *progressbar.ProgressBar
}

// warnSkip reports an entry that could not be extracted. Warnings always go
// to stderr so partial extractions are never silent, and the skip count makes
// the run exit non-zero.
func (e *Extractor) warnSkip(format string, args ...any) {
	e.entriesSkipped++
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

// destPath joins rel under the destination root, sanitizing each path
// component so it is representable on the host OS (e.g. Windows rejects
// trailing spaces/dots, reserved characters and reserved device names). When
// a component is remapped the change is reported and counted, so extraction
// stays lossless in content and never fails purely because the source used a
// name the destination filesystem cannot store verbatim.
func (e *Extractor) destPath(rel string) string {
	if rel == "" {
		return e.Destination
	}
	sanitized, changed := sanitizePathForHost(rel)
	if changed {
		e.namesRemapped++
		fmt.Fprintf(os.Stderr, "Note: %q cannot be represented on this filesystem; extracted as %q\n", rel, sanitized)
	}
	return filepath.Join(e.Destination, filepath.FromSlash(sanitized))
}

// ExtractAll extracts the entire volume into the destination directory.
func (e *Extractor) ExtractAll() error {
	return e.extractTree(".", "")
}

// ExtractByPath extracts a specific file or directory by absolute volume path.
func (e *Extractor) ExtractByPath(volumePath string, recursive bool) error {
	name := fsNameFromVolumePath(volumePath)

	info, err := e.Volume.Stat(name)
	if err != nil {
		return fmt.Errorf("unable to find path %s: %w", volumePath, err)
	}

	base := path.Base(name)

	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s is a directory; use --recursive to extract its contents", volumePath)
		}
		return e.extractTree(name, base)
	}

	if info.Mode()&fs.ModeSymlink != 0 {
		return e.extractSymlink(name, e.destPath(base))
	}

	return e.extractFile(name, e.destPath(base), info)
}

// extractTree walks the subtree rooted at root (an fs.FS name) and recreates
// it under Destination/destBase. Individual failures are reported and counted
// but do not abort the walk.
func (e *Extractor) extractTree(root, destBase string) error {
	type pendingDir struct {
		destPath string
		info     fs.FileInfo
	}
	var dirs []pendingDir

	err := fs.WalkDir(e.Volume, root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if name == root {
				return walkErr
			}
			e.warnSkip("unable to walk %s: %v", name, walkErr)
			return nil
		}

		// Destination path: name relative to the walk root, under destBase
		rel := strings.TrimPrefix(strings.TrimPrefix(name, root), "/")
		if root == "." {
			rel = name
			if rel == "." {
				rel = ""
			}
		}
		destRel := rel
		if destBase != "" {
			destRel = path.Join(destBase, rel)
		}
		destPath := e.destPath(destRel)

		switch {
		case entry.IsDir():
			if err := os.MkdirAll(destPath, 0755); err != nil {
				e.warnSkip("unable to create directory %s: %v", destPath, err)
				return fs.SkipDir
			}
			if e.Verbose {
				fmt.Printf("Created directory: %s\n", destPath)
			}
			if e.PreserveMeta {
				if info, err := entry.Info(); err == nil {
					// Applied after the walk so extracting children does not
					// bump the directory's restored timestamps
					dirs = append(dirs, pendingDir{destPath: destPath, info: info})
				}
			}

		case entry.Type()&fs.ModeSymlink != 0:
			if err := e.extractSymlink(name, destPath); err != nil {
				e.warnSkip("unable to extract symlink %s: %v", name, err)
			}

		case entry.Type().IsRegular():
			if e.Pattern != nil && !e.Pattern.MatchString(rel) {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				e.warnSkip("unable to stat %s: %v", name, err)
				return nil
			}
			if err := e.extractFile(name, destPath, info); err != nil {
				e.warnSkip("unable to extract %s: %v", name, err)
			}

		default:
			// Sockets, pipes, devices: nothing meaningful to extract
			if e.Verbose {
				fmt.Printf("Skipping special file: %s (%s)\n", name, entry.Type())
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Restore directory metadata deepest-first
	for i := len(dirs) - 1; i >= 0; i-- {
		e.applyMetadata(dirs[i].destPath, dirs[i].info)
	}

	return nil
}

// extractSymlink recreates the symlink at the fs name as destPath, applying
// the configured SymlinkMode. In auto mode, if the OS refuses to create a
// real symlink (e.g. unprivileged Windows), the target path is written into
// a regular file instead so no information is lost and extraction completes.
func (e *Extractor) extractSymlink(name, destPath string) error {
	target, err := e.Volume.Readlink(name)
	if err != nil {
		return fmt.Errorf("unable to read symlink target: %w", err)
	}

	switch e.SymlinkMode {
	case SymlinkFile:
		return e.writeSymlinkAsFile(destPath, target, nil)

	case SymlinkReal:
		if err := os.Symlink(target, destPath); err != nil {
			return err
		}

	default: // SymlinkAuto
		if err := os.Symlink(target, destPath); err != nil {
			// The symlink was read fine; the OS just won't materialize it.
			// Preserve it losslessly as a regular file (git-style fallback).
			return e.writeSymlinkAsFile(destPath, target, err)
		}
	}

	if e.Verbose {
		fmt.Printf("Created symlink: %s -> %s\n", destPath, target)
	} else if e.progressBar != nil {
		e.progressBar.Add(1)
	}
	e.filesExtracted++

	return nil
}

// writeSymlinkAsFile writes a symlink's target path into a regular file at
// destPath. cause is the original os.Symlink error when this is a fallback
// (nil when SymlinkFile mode was requested explicitly).
func (e *Extractor) writeSymlinkAsFile(destPath, target string, cause error) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("unable to create parent directory: %w", err)
	}
	if err := os.WriteFile(destPath, []byte(target), 0644); err != nil {
		return err
	}

	if cause != nil {
		e.symlinksDegraded++
		fmt.Fprintf(os.Stderr, "Note: %s could not be created as a symlink (%v); wrote its target %q as a regular file instead\n",
			destPath, cause, target)
	} else if e.Verbose {
		fmt.Printf("Wrote symlink target as file: %s -> %s\n", destPath, target)
	}
	if e.progressBar != nil {
		e.progressBar.Add(1)
	}
	e.filesExtracted++

	return nil
}

// extractFile copies the regular file at the fs name to destPath.
func (e *Extractor) extractFile(name, destPath string, info fs.FileInfo) error {
	source, err := e.Volume.Open(name)
	if err != nil {
		return err
	}
	defer source.Close()

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("unable to create parent directory: %w", err)
	}

	outFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("unable to create file: %w", err)
	}
	defer outFile.Close()

	var reader io.Reader = source
	var sourceHasher = sha256.New()
	if e.VerifyChecksum {
		reader = io.TeeReader(source, sourceHasher)
	}

	written, err := io.Copy(outFile, reader)
	if err != nil {
		outFile.Close()
		os.Remove(destPath)
		return fmt.Errorf("unable to copy file data: %w", err)
	}

	if e.VerifyChecksum {
		relPath, err := filepath.Rel(e.Destination, destPath)
		if err == nil {
			e.sourceChecksums[relPath] = hex.EncodeToString(sourceHasher.Sum(nil))
		}
	}

	e.filesExtracted++
	e.bytesExtracted += uint64(written)

	if e.Verbose {
		fmt.Printf("  [%d] %s (%s)\n", e.filesExtracted, filepath.Base(destPath), formatBytes(uint64(written)))
	} else if e.progressBar != nil {
		e.progressBar.Add(1)
	}

	if e.PreserveMeta {
		e.applyMetadata(destPath, info)
	}

	return nil
}

// applyMetadata restores permissions and timestamps from the volume entry.
func (e *Extractor) applyMetadata(destPath string, info fs.FileInfo) {
	if err := os.Chmod(destPath, info.Mode().Perm()); err != nil && e.Verbose {
		fmt.Printf("Warning: unable to set permissions on %s: %v\n", destPath, err)
	}

	modTime := info.ModTime()
	accessTime := modTime
	if inode, ok := info.Sys().(*apfs.Inode); ok && inode.AccessTime != 0 {
		accessTime = time.Unix(0, int64(inode.AccessTime))
	}

	if err := os.Chtimes(destPath, accessTime, modTime); err != nil && e.Verbose {
		fmt.Printf("Warning: unable to set timestamps on %s: %v\n", destPath, err)
	}
}

// fsNameFromVolumePath converts an absolute volume path ("/a/b") to an fs.FS
// name ("a/b", or "." for the root).
func fsNameFromVolumePath(volumePath string) string {
	name := strings.Trim(path.Clean("/"+volumePath), "/")
	if name == "" {
		return "."
	}
	return name
}

// NewExtractor creates an extractor for a volume writing into destination.
func NewExtractor(volume VolumeFS, destination string) *Extractor {
	return &Extractor{
		Volume:          volume,
		Destination:     destination,
		sourceChecksums: make(map[string]string),
	}
}

// SetProgressBar attaches a progress bar (optional).
func (e *Extractor) SetProgressBar(bar *progressbar.ProgressBar) {
	e.progressBar = bar
}

// FinishProgress completes the progress bar if one is attached.
func (e *Extractor) FinishProgress() {
	if e.progressBar != nil {
		e.progressBar.Finish()
	}
}

// Skipped returns the number of entries that could not be extracted.
func (e *Extractor) Skipped() int {
	return e.entriesSkipped
}

// SymlinksDegraded returns the number of symlinks written as regular files
// because the OS would not create a real symlink.
func (e *Extractor) SymlinksDegraded() int {
	return e.symlinksDegraded
}

// NamesRemapped returns the number of entries whose names were sanitized to
// be storable on the host filesystem.
func (e *Extractor) NamesRemapped() int {
	return e.namesRemapped
}

// GetStats returns extraction statistics
func (e *Extractor) GetStats() (filesExtracted int, bytesExtracted uint64) {
	return e.filesExtracted, e.bytesExtracted
}

// VerifyExtractedFiles verifies that extracted files match source by comparing checksums
func (e *Extractor) VerifyExtractedFiles() error {
	if len(e.sourceChecksums) == 0 {
		fmt.Println("No checksums computed during extraction")
		return nil
	}

	headerText := fmt.Sprintf("Checksum Verification: %d files", len(e.sourceChecksums))
	boxWidth := len(headerText)
	fmt.Printf("╭─%s─╮\n", strings.Repeat("─", boxWidth))
	fmt.Printf("│ %-*s │\n", boxWidth, headerText)
	fmt.Printf("╰─%s─╯\n\n", strings.Repeat("─", boxWidth))

	verified := 0
	mismatches := 0
	missing := 0

	// Sort file paths for consistent output
	var sortedPaths []string
	for relPath := range e.sourceChecksums {
		sortedPaths = append(sortedPaths, relPath)
	}
	sort.Strings(sortedPaths)

	for _, relPath := range sortedPaths {
		sourceChecksum := e.sourceChecksums[relPath]
		destPath := filepath.Join(e.Destination, relPath)

		// Get file info
		fileInfo, err := os.Stat(destPath)
		if os.IsNotExist(err) {
			fmt.Printf("  ✗ MISSING\n")
			fmt.Printf("    %-20s  %s\n", "File", relPath)
			fmt.Printf("    %-20s  %s\n\n", "APFS checksum", sourceChecksum)
			missing++
			continue
		}

		// Compute checksum of extracted file
		extractedChecksum, err := computeFileChecksum(destPath)
		if err != nil {
			fmt.Printf("  ✗ ERROR\n")
			fmt.Printf("    %-20s  %s\n", "File", relPath)
			fmt.Printf("    %-20s  %v\n\n", "Error", err)
			continue
		}

		// Compare checksums
		match := sourceChecksum == extractedChecksum
		status := "✓"
		if !match {
			status = "✗"
			mismatches++
		} else {
			verified++
		}

		// Show file with both checksums for comparison
		fmt.Printf("  %s %s\n", status, relPath)
		fmt.Printf("      %-20s  %s\n", "Size", formatBytes(uint64(fileInfo.Size())))
		fmt.Printf("      %-20s  %s\n", "APFS SHA-256", sourceChecksum)
		fmt.Printf("      %-20s  %s\n", "Disk SHA-256", extractedChecksum)
		if !match {
			fmt.Printf("      %-20s  CHECKSUM MISMATCH!\n", "Status")
		}
		fmt.Println()
	}

	// Summary section
	fmt.Printf("\n╭─ Verification Summary ─────────────────────────────╮\n")
	fmt.Printf("│  %-30s  %19d │\n", "Total files verified", verified)
	if mismatches > 0 {
		fmt.Printf("│  %-30s  %19d │\n", "✗ Checksum mismatches", mismatches)
	}
	if missing > 0 {
		fmt.Printf("│  %-30s  %19d │\n", "✗ Missing files", missing)
	}
	fmt.Printf("╰────────────────────────────────────────────────────╯\n")

	if mismatches == 0 && missing == 0 {
		fmt.Println("\n✓ All files verified successfully!")
		return nil
	}

	return fmt.Errorf("verification failed: %d mismatches, %d missing", mismatches, missing)
}

// computeFileChecksum computes SHA-256 checksum of a file
func computeFileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
