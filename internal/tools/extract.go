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
	"github.com/spf13/cobra"
)

var (
	extractContainerPath  string
	extractDestination    string
	extractPath           string
	extractPattern        string
	extractRecursive      bool
	extractPreserveMeta   bool
	extractVerbose        bool
	extractVolumeIndex    int
	extractVerifyChecksum bool
)

// ExtractCmd represents the extract command
var ExtractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract files from APFS volume",
	Long: `Extract files from an APFS volume to a local directory.

Supports:
  - Full volume extraction (default)
  - Single file/directory extraction by path
  - Pattern-based extraction using regex
  - Metadata preservation (timestamps, permissions)

Examples:
  # Extract entire volume
  apfs extract --container image.dmg --destination ./output

  # Extract specific directory
  apfs extract --container image.dmg --path /Applications --destination ./apps --recursive

  # Extract files matching pattern
  apfs extract --container image.dmg --pattern "\.txt$" --destination ./textfiles

  # Extract with metadata preservation
  apfs extract --container image.dmg --destination ./output --preserve-meta`,
	RunE: runExtract,
}

func init() {
	ExtractCmd.Flags().StringVarP(&extractContainerPath, "container", "c", "", "Path to APFS container (required)")
	ExtractCmd.Flags().StringVarP(&extractDestination, "destination", "d", "", "Destination directory for extracted files (required)")
	ExtractCmd.Flags().StringVarP(&extractPath, "path", "p", "/", "Path to extract (default: root)")
	ExtractCmd.Flags().StringVar(&extractPattern, "pattern", "", "Regex pattern to match files (e.g. \"\\.txt$\")")
	ExtractCmd.Flags().BoolVarP(&extractRecursive, "recursive", "r", false, "Extract recursively")
	ExtractCmd.Flags().BoolVar(&extractPreserveMeta, "preserve-meta", false, "Preserve file metadata (timestamps, permissions)")
	ExtractCmd.Flags().BoolVarP(&extractVerbose, "verbose", "v", false, "Verbose output")
	ExtractCmd.Flags().IntVar(&extractVolumeIndex, "volume", 0, "Volume index (default: 0)")
	ExtractCmd.Flags().BoolVar(&extractVerifyChecksum, "verify", false, "Compute and verify checksums during extraction")

	ExtractCmd.MarkFlagRequired("container")
	ExtractCmd.MarkFlagRequired("destination")
}

func runExtract(cmd *cobra.Command, args []string) error {
	// Open the image with content-based format detection
	container, closer, err := apfs.OpenImage(extractContainerPath, nil)
	if err != nil {
		return fmt.Errorf("unable to open container: %w", err)
	}
	defer closer.Close()
	defer container.Free()

	// Get volume
	volume, err := container.GetVolume(extractVolumeIndex)
	if err != nil {
		return fmt.Errorf("unable to get volume: %w", err)
	}

	// Create destination directory
	if err := os.MkdirAll(extractDestination, 0755); err != nil {
		return fmt.Errorf("unable to create destination directory: %w", err)
	}

	// Compile regex pattern if provided
	var pattern *regexp.Regexp
	if extractPattern != "" {
		pattern, err = regexp.Compile(extractPattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	// Create extractor
	extractor := &Extractor{
		Volume:          volume,
		Destination:     extractDestination,
		Pattern:         pattern,
		PreserveMeta:    extractPreserveMeta,
		Verbose:         extractVerbose,
		VerifyChecksum:  extractVerifyChecksum,
		sourceChecksums: make(map[string]string),
	}

	// Create progress bar (counter/spinner since we don't know total count upfront)
	if !extractVerbose {
		extractor.progressBar = progressbar.NewOptions(-1,
			progressbar.OptionSetDescription("Extracting"),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(40),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionShowElapsedTimeOnFinish(),
			progressbar.OptionSetWriter(os.Stderr),
		)
	}

	// Extract based on mode. The root path means "the whole volume": contents
	// land directly in the destination directory.
	if extractPath != "" && extractPath != "/" {
		err = extractor.ExtractByPath(extractPath, extractRecursive)
	} else {
		err = extractor.ExtractAll()
	}
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	// Finish progress bar
	if extractor.progressBar != nil {
		extractor.progressBar.Finish()
	}

	fmt.Printf("\nExtraction complete! Files saved to: %s\n", extractDestination)
	fmt.Printf("Total: %d files, %s\n", extractor.filesExtracted, formatBytes(extractor.bytesExtracted))

	// Verify checksums if requested
	if extractVerifyChecksum {
		fmt.Println("\n=== Verifying Checksums ===")
		if err := extractor.VerifyExtractedFiles(); err != nil {
			fmt.Printf("Warning: Verification encountered errors: %v\n", err)
		}
	}

	if extractor.entriesSkipped > 0 {
		return fmt.Errorf("partial extraction: %d entries could not be extracted (see warnings above)", extractor.entriesSkipped)
	}

	return nil
}

// Extractor handles file extraction from APFS volumes
type Extractor struct {
	Volume          *apfs.Volume
	Destination     string
	Pattern         *regexp.Regexp
	PreserveMeta    bool
	Verbose         bool
	VerifyChecksum  bool
	filesExtracted  int
	entriesSkipped  int
	bytesExtracted  uint64
	sourceChecksums map[string]string // relativePath -> SHA256 of source data
	progressBar     *progressbar.ProgressBar
}

// warnSkip reports an entry that could not be extracted. Warnings always go
// to stderr so partial extractions are never silent, and the skip count makes
// the run exit non-zero.
func (e *Extractor) warnSkip(format string, args ...any) {
	e.entriesSkipped++
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
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
		return e.extractSymlink(name, filepath.Join(e.Destination, base))
	}

	return e.extractFile(name, filepath.Join(e.Destination, base), info)
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
		destPath := filepath.Join(e.Destination, destBase, rel)

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

// extractSymlink recreates the symlink at the fs name as destPath.
func (e *Extractor) extractSymlink(name, destPath string) error {
	target, err := e.Volume.Readlink(name)
	if err != nil {
		return fmt.Errorf("unable to read symlink target: %w", err)
	}

	if err := os.Symlink(target, destPath); err != nil {
		return err
	}

	if e.Verbose {
		fmt.Printf("Created symlink: %s -> %s\n", destPath, target)
	} else if e.progressBar != nil {
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
