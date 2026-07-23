// Extract tool for extracting files from APFS volumes
// Supports full volume extraction, path-based extraction, and regex pattern matching
package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
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
  - Full volume extraction (recursive)
  - Single file/directory extraction by path
  - Pattern-based extraction using regex
  - Metadata preservation (timestamps, permissions)

Examples:
  # Extract entire volume
  apfs extract --container /dev/disk2 --destination ./output --recursive

  # Extract specific directory
  apfs extract --container /dev/disk2 --path /Applications --destination ./apps

  # Extract files matching pattern
  apfs extract --container /dev/disk2 --pattern "\.txt$" --destination ./textfiles

  # Extract with metadata preservation
  apfs extract --container /dev/disk2 --destination ./output --preserve-meta --recursive`,
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
	// Open file with DMG detection and decompression
	reader, offset, closer, err := disk.OpenWithOffset(extractContainerPath)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer closer.Close()

	if extractVerbose {
		if _, isDMG := reader.(*disk.DMGReader); isDMG {
			fmt.Println("DMG detected, using on-the-fly decompression")
		} else {
			fmt.Println("Raw APFS container detected")
		}
	}

	// Create IO handle
	ioHandle, err := apfs.NewIOHandle()
	if err != nil {
		return fmt.Errorf("unable to create IO handle: %w", err)
	}

	// Create container
	container, err := apfs.NewContainer(ioHandle)
	if err != nil {
		return fmt.Errorf("unable to create container: %w", err)
	}
	defer container.Free()

	// Open container for reading at the determined offset
	if err := container.OpenRead(reader, offset); err != nil {
		return fmt.Errorf("unable to open container: %w", err)
	}

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
		FileHandle:      reader,
		VerifyChecksum:  extractVerifyChecksum,
		sourceChecksums: make(map[string]string),
	}

	// Create progress bar (counter/spinner since we don't know total count upfront)
	if !extractVerbose {
		extractor.progressBar = progressbar.NewOptions(-1,
			progressbar.OptionSetDescription("Extracting"),
			progressbar.OptionShowCount(),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(40),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionShowElapsedTimeOnFinish(),
		)
	}

	// Extract based on mode. The root path means "the whole volume": route it
	// to ExtractAll so contents land directly in the destination directory.
	if extractPath != "" && extractPath != "/" {
		// Extract specific path
		if err := extractor.ExtractByPath(extractPath, extractRecursive); err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}
	} else {
		// Extract entire volume
		if err := extractor.ExtractAll(); err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}
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
	FileHandle      io.ReaderAt
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

// File type constants (from POSIX)
const (
	S_IFDIR = 0x4000 // Directory
	S_IFREG = 0x8000 // Regular file
	S_IFLNK = 0xA000 // Symbolic link
	S_IFMT  = 0xF000 // File type mask
)

// isDirectory checks if a file entry is a directory
func isDirectory(entry *apfs.FileEntry) (bool, error) {
	fileMode, err := entry.GetFileMode()
	if err != nil {
		return false, err
	}
	return (fileMode & S_IFMT) == S_IFDIR, nil
}

// isSymbolicLink checks if a file entry is a symbolic link
func isSymbolicLink(entry *apfs.FileEntry) (bool, error) {
	fileMode, err := entry.GetFileMode()
	if err != nil {
		return false, err
	}
	return (fileMode & S_IFMT) == S_IFLNK, nil
}

// ExtractAll extracts the entire volume recursively
func (e *Extractor) ExtractAll() error {
	if e.Verbose {
		fmt.Println("Extracting entire volume...")
	}

	// Get root directory (inode 2)
	rootEntry, err := e.Volume.GetFileEntryByIdentifier(2)
	if err != nil {
		fmt.Printf("ERROR: unable to get root directory: %v\n", err)
		return fmt.Errorf("unable to get root directory: %w", err)
	}

	err = e.extractRecursive(rootEntry, "", e.Destination)
	if err != nil {
		fmt.Printf("ERROR: extractRecursive failed: %v\n", err)
		return err
	}
	return nil
}

// ExtractByPath extracts a specific file or directory by path
func (e *Extractor) ExtractByPath(path string, recursive bool) error {
	if e.Verbose {
		fmt.Printf("Extracting path: %s\n", path)
	}

	// Get file entry by path
	entry, err := e.Volume.GetFileEntryByPath(path)
	if err != nil {
		return fmt.Errorf("unable to find path %s: %w", path, err)
	}

	// Get filename
	name := filepath.Base(path)
	if path == "/" {
		name = "root"
	}

	destPath := filepath.Join(e.Destination, name)

	// Extract based on type
	isDir, err := isDirectory(entry)
	if err != nil {
		return fmt.Errorf("unable to determine file type: %w", err)
	}

	if isDir {
		if !recursive {
			return fmt.Errorf("%s is a directory; use --recursive to extract its contents", path)
		}
		return e.extractRecursive(entry, name, e.Destination)
	}

	// Extract single file
	return e.extractFile(entry, destPath)
}

// extractRecursive recursively extracts a directory and its contents
func (e *Extractor) extractRecursive(entry *apfs.FileEntry, relativePath string, parentDest string) error {
	// Build destination path
	destPath := filepath.Join(parentDest, relativePath)

	if e.Verbose {
	}

	// Check pattern match
	if e.Pattern != nil && relativePath != "" {
		isDir, _ := isDirectory(entry)
		if !e.Pattern.MatchString(relativePath) && !isDir {
			return nil // Skip non-matching files
		}
	}

	isDir, err := isDirectory(entry)
	if err != nil {
		fmt.Printf("ERROR: unable to determine file type: %v\n", err)
		return fmt.Errorf("unable to determine file type: %w", err)
	}

	if isDir {
		// Create directory
		if err := os.MkdirAll(destPath, 0755); err != nil {
			return fmt.Errorf("unable to create directory %s: %w", destPath, err)
		}

		if e.Verbose {
			fmt.Printf("Created directory: %s\n", destPath)
		}

		// Get directory entries
		identifier, err := entry.GetIdentifier()
		if err != nil {
			fmt.Printf("ERROR: unable to get identifier: %v\n", err)
			return fmt.Errorf("unable to get identifier: %w", err)
		}

		if e.Verbose {
		}

		dirRecords, err := e.Volume.FileSystemBTree.GetDirectoryEntries(e.Volume.FileIOHandle, identifier, 0)
		if err != nil {
			fmt.Printf("ERROR: unable to read directory contents: %v\n", err)
			return fmt.Errorf("unable to read directory contents: %w", err)
		}

		if e.Verbose {
		}

		// Extract each child
		for _, record := range dirRecords {
			childName := string(record.Name)
			childRelPath := filepath.Join(relativePath, childName)

			childEntry, err := e.Volume.GetFileEntryByIdentifier(record.Identifier)
			if err != nil {
				e.warnSkip("unable to get inode %d for %s: %v", record.Identifier, childRelPath, err)
				continue
			}

			// Recursively extract child
			if err := e.extractRecursive(childEntry, childRelPath, parentDest); err != nil {
				e.warnSkip("failed to extract %s: %v", childRelPath, err)
				// Continue with other files even if one fails
				continue
			}
		}

		// Preserve directory metadata
		if e.PreserveMeta {
			e.preserveMetadata(entry, destPath)
		}

	} else {
		// Check if it's a symlink
		isSymlink, err := isSymbolicLink(entry)
		if err != nil {
			return fmt.Errorf("unable to determine if symlink: %w", err)
		}

		if isSymlink {
			// Extract symlink
			target, err := entry.GetSymbolicLinkTarget()
			if err != nil {
				e.warnSkip("unable to read symlink target for %s: %v", destPath, err)
				return nil // Skip this symlink but continue extraction
			}

			if err := os.Symlink(target, destPath); err != nil {
				e.warnSkip("unable to create symlink %s -> %s: %v", destPath, target, err)
				return nil // Skip this symlink but continue extraction
			}

			if e.Verbose {
				fmt.Printf("Created symlink: %s -> %s\n", destPath, target)
			}
			e.filesExtracted++
		} else {
			// Extract regular file
			if err := e.extractFile(entry, destPath); err != nil {
				e.warnSkip("file extraction failed for %s: %v", destPath, err)
				return nil // Skip this file but continue extraction
			}
		}
	}

	return nil
}

// extractFile extracts a single file
func (e *Extractor) extractFile(entry *apfs.FileEntry, destPath string) error {
	// Check pattern match
	if e.Pattern != nil {
		if !e.Pattern.MatchString(destPath) {
			return nil // Skip non-matching file
		}
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("unable to create parent directory: %w", err)
	}

	// Create output file
	outFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("unable to create file %s: %w", destPath, err)
	}
	defer outFile.Close()

	// Get file size
	size, err := entry.GetSize()
	if err != nil {
		return fmt.Errorf("unable to get file size: %w", err)
	}

	// Read and write file data
	var bytesWritten uint64
	buffer := make([]byte, 1024*1024) // 1MB buffer

	// Initialize checksum hasher if verification is enabled
	var sourceHasher hash.Hash
	if e.VerifyChecksum {
		sourceHasher = sha256.New()
	}

	for bytesWritten < size {
		// Calculate read size
		readSize := uint64(len(buffer))
		if bytesWritten+readSize > size {
			readSize = size - bytesWritten
		}

		// Read from APFS at current offset
		n, err := entry.ReadAt(buffer[:readSize], int64(bytesWritten))
		if err != nil && err != io.EOF {
			// Check for specific error about missing file extents or compressed data
			if strings.Contains(err.Error(), "no file extents") ||
				strings.Contains(err.Error(), "unable to determine data stream") {
				e.warnSkip("unable to read data for %s (may be sparse or special file): %v", destPath, err)
				// Close and remove the partial file
				outFile.Close()
				os.Remove(destPath)
				return nil // Skip this file but continue extraction
			}
			fmt.Printf("ERROR extractFile: Read failed: %v\n", err)
			return fmt.Errorf("unable to read file data: %w", err)
		}

		if n == 0 {
			break
		}

		// Update source checksum if verification enabled
		if sourceHasher != nil {
			sourceHasher.Write(buffer[:n])
		}

		// Write to output file
		if _, err := outFile.Write(buffer[:n]); err != nil {
			return fmt.Errorf("unable to write file data: %w", err)
		}

		bytesWritten += uint64(n)
	}

	// Store source checksum if verification enabled
	if sourceHasher != nil {
		relPath, err := filepath.Rel(e.Destination, destPath)
		if err == nil {
			e.sourceChecksums[relPath] = hex.EncodeToString(sourceHasher.Sum(nil))
		}
	}

	e.filesExtracted++
	e.bytesExtracted += bytesWritten

	// Update progress
	if e.Verbose {
		fmt.Printf("  [%d] %s (%s)\n", e.filesExtracted, filepath.Base(destPath), formatBytes(bytesWritten))
	} else if e.progressBar != nil {
		e.progressBar.Add(1)
	}

	// Preserve metadata
	if e.PreserveMeta {
		e.preserveMetadata(entry, destPath)
	}

	return nil
}

// preserveMetadata preserves file metadata (timestamps, permissions)
func (e *Extractor) preserveMetadata(entry *apfs.FileEntry, destPath string) {
	// Set permissions
	fileMode, err := entry.GetFileMode()
	if err == nil {
		if err := os.Chmod(destPath, os.FileMode(fileMode)); err != nil {
			if e.Verbose {
				fmt.Printf("Warning: unable to set permissions on %s: %v\n", destPath, err)
			}
		}
	} else if e.Verbose {
		fmt.Printf("Warning: unable to get file mode for %s: %v\n", destPath, err)
	}

	// Set timestamps
	modTime, err := entry.GetModificationTime()
	if err != nil {
		if e.Verbose {
			fmt.Printf("Warning: unable to get modification time for %s: %v\n", destPath, err)
		}
		return
	}

	accessTime, err := entry.GetAccessTime()
	if err != nil {
		if e.Verbose {
			fmt.Printf("Warning: unable to get access time for %s: %v\n", destPath, err)
		}
		return
	}

	if err := os.Chtimes(destPath, time.Unix(0, accessTime), time.Unix(0, modTime)); err != nil {
		if e.Verbose {
			fmt.Printf("Warning: unable to set timestamps on %s: %v\n", destPath, err)
		}
	}
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
	fmt.Printf("╭─%s─╮\n", repeatString("─", boxWidth))
	fmt.Printf("│ %-*s │\n", boxWidth, headerText)
	fmt.Printf("╰─%s─╯\n\n", repeatString("─", boxWidth))

	verified := 0
	mismatches := 0
	missing := 0

	// Sort file paths for consistent output
	var sortedPaths []string
	for path := range e.sourceChecksums {
		sortedPaths = append(sortedPaths, path)
	}
	sortStrings(sortedPaths)

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

// repeatString repeats a string n times
func repeatString(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

// sortStrings sorts a slice of strings in place
func sortStrings(s []string) {
	// Simple bubble sort for small lists
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// truncateHash returns first 16 chars of hash for display
func truncateHash(hash string) string {
	if len(hash) > 16 {
		return hash[:16] + "..."
	}
	return hash
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
