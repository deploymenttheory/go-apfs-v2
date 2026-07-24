// apfs extract IMAGE [PATH] — extract files to a local directory.
package cli

import (
	"fmt"
	"regexp"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	extractDestination  string
	extractPattern      string
	extractRecursive    bool
	extractPreserveMeta bool
	extractVerify       bool
)

var extractCmd = &cobra.Command{
	Use:   "extract IMAGE [PATH]",
	Short: "Extract files from an APFS volume",
	Long: `Extract files from an APFS volume to a local directory. Without PATH
the whole volume is extracted.

Exit code 6 indicates a partial extraction: some entries were skipped and a
warning was printed to stderr for each.

Examples:
  apfs extract image.dmg -C ./out
  apfs extract image.dmg /Applications/Some.app -C ./out --recursive
  apfs extract image.dmg -C ./out --pattern '\.plist$'
  apfs extract image.dmg -C ./out --preserve-meta --verify`,
	Args: rangeArgs(1, 2, "IMAGE [PATH]"),
	RunE: runExtract,
}

func init() {
	extractCmd.Flags().StringVarP(&extractDestination, "destination", "C", "", "destination directory (required)")
	extractCmd.Flags().StringVar(&extractPattern, "pattern", "", "only extract files whose path matches this regex")
	extractCmd.Flags().BoolVarP(&extractRecursive, "recursive", "r", false, "recurse into a directory PATH")
	extractCmd.Flags().BoolVar(&extractPreserveMeta, "preserve-meta", false, "preserve permissions and timestamps")
	extractCmd.Flags().Bool("xattrs", false, "reserved: extended attribute extraction (not yet implemented)")
	extractCmd.Flags().BoolVar(&extractVerify, "verify", false, "verify extracted files against source checksums")
	extractCmd.MarkFlagRequired("destination")
}

func runExtract(cmd *cobra.Command, args []string) error {
	imagePath := args[0]
	volumePath := "/"
	if len(args) == 2 {
		volumePath = args[1]
	}

	volume, closer, err := openFilesystem(imagePath)
	if err != nil {
		return err
	}
	defer closer.Close()

	var pattern *regexp.Regexp
	if extractPattern != "" {
		pattern, err = regexp.Compile(extractPattern)
		if err != nil {
			return usageErrorf("invalid --pattern: %v", err)
		}
	}

	extractor := tools.NewExtractor(volume, extractDestination)
	extractor.Pattern = pattern
	extractor.PreserveMeta = extractPreserveMeta
	extractor.Verbose = opts.Verbose
	extractor.VerifyChecksum = extractVerify

	if !opts.Verbose && !opts.Quiet && stderrIsTTY() {
		extractor.SetProgressBar(progressbar.NewOptions(-1,
			progressbar.OptionSetDescription("Extracting"),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(40),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionShowElapsedTimeOnFinish(),
			progressbar.OptionSetWriter(cmd.ErrOrStderr()),
		))
	}

	if volumePath != "" && volumePath != "/" {
		err = extractor.ExtractByPath(volumePath, extractRecursive)
	} else {
		err = extractor.ExtractAll()
	}
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	extractor.FinishProgress()

	files, bytes := extractor.GetStats()

	if opts.Output == "json" {
		summary := map[string]any{
			"destination": extractDestination,
			"files":       files,
			"bytes":       bytes,
			"skipped":     extractor.Skipped(),
		}
		if err := jsonOut(summary); err != nil {
			return err
		}
	} else if !opts.Quiet {
		fmt.Printf("\nExtraction complete! Files saved to: %s\n", extractDestination)
		fmt.Printf("Total: %d files, %s\n", files, formatSize(bytes))
	}

	if extractVerify {
		if !opts.Quiet {
			fmt.Println("\n=== Verifying Checksums ===")
		}
		if err := extractor.VerifyExtractedFiles(); err != nil {
			return withCode(ExitPartial, fmt.Errorf("verification failed: %w", err))
		}
	}

	if skipped := extractor.Skipped(); skipped > 0 {
		return withCode(ExitPartial, fmt.Errorf("partial extraction: %d entries could not be extracted (see warnings above)", skipped))
	}

	return nil
}
