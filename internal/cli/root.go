// Package cli provides the apfs command-line interface. All cobra/viper
// wiring lives here; parsing logic lives in pkg/apfs and pkg/disk.
//
// Configuration precedence: flag > APFS_* environment variable > config file
// (~/.config/apfs/config.yaml, optional).
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const version = "0.2.0"

// globalOptions are the persistent flags shared by all commands, resolved
// through viper so environment variables and the config file apply.
type globalOptions struct {
	Output           string // text | json
	Quiet            bool
	Verbose          bool
	Volume           string // index, name or UUID
	Password         string
	PasswordStdin    bool
	RecoveryPassword string
	Offset           int64
}

var opts globalOptions

var rootCmd = &cobra.Command{
	Use:   "apfs",
	Short: "Read, extract and build Apple File System (APFS) and HFS+ disk images",
	Long: `A cross-platform, self-contained toolkit for Apple disk images. It reads
APFS and HFS+ filesystems directly from DMGs (zlib, bzip2, ADC, LZFSE or LZMA
compressed), GPT- or Apple-Partition-Map raw images, or bare containers —
without mounting and without macOS — and can also build and repack DMGs.

Read commands:
  info     Container and volume summary (text or JSON)
  list     List directory contents (recursive, JSON lines)
  cat      Write file contents to stdout, for pipelines
  extract  Extract files/directories to the local filesystem
  inspect  Low-level structural inspection (container walk, blocks, B-trees)
  mount    Mount read-only via FUSE (Linux and macOS)

Write commands:
  pack     Build a DMG from a directory (HFS+), or repack a DMG losslessly
  create   Format an empty HFS+ or APFS volume in a new DMG

Images are auto-detected by content; every command takes the image as its
first argument. Data goes to stdout, diagnostics and progress to stderr.

Configuration precedence: flag > APFS_<FLAG> environment variable >
~/.config/apfs/config.yaml.

Exit codes:
  0 success        3 unrecognized image     5 unsupported on this platform
  1 error          4 authentication needed  6 partial result
  2 usage error       or failed`,
	Version:           version,
	SilenceUsage:      true,
	SilenceErrors:     true,
	DisableAutoGenTag: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return resolveGlobalOptions(cmd)
	},
}

func init() {
	flags := rootCmd.PersistentFlags()
	flags.StringP("output", "o", "text", "output format: text or json")
	flags.BoolP("quiet", "q", false, "suppress progress and non-essential messages")
	flags.Bool("verbose", false, "verbose diagnostics on stderr")
	flags.StringP("volume", "v", "", "volume to operate on: index, name or UUID (default: first)")
	flags.StringP("password", "p", "", "password for encrypted volumes")
	flags.Bool("password-stdin", false, "read the password from standard input")
	flags.String("recovery-password", "", "recovery password for encrypted volumes")
	flags.Int64("offset", 0, "byte offset of the container in the image (expert; overrides detection)")

	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return withCode(ExitUsage, err)
	})

	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(catCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(packCmd)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(mountCmd)
}

// resolveGlobalOptions binds flags into viper and resolves the effective
// configuration from flags, APFS_* environment variables and the optional
// config file.
func resolveGlobalOptions(cmd *cobra.Command) error {
	v := viper.New()
	v.SetEnvPrefix("APFS")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	if err := v.BindPFlags(cmd.Root().PersistentFlags()); err != nil {
		return err
	}

	if home, err := os.UserHomeDir(); err == nil {
		v.SetConfigFile(filepath.Join(home, ".config", "apfs", "config.yaml"))
		// The config file is optional; only complain if it exists but is invalid
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(*os.PathError); !ok && !os.IsNotExist(err) {
				if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound {
					return fmt.Errorf("unable to read config file: %w", err)
				}
			}
		}
	}

	opts = globalOptions{
		Output:           v.GetString("output"),
		Quiet:            v.GetBool("quiet"),
		Verbose:          v.GetBool("verbose"),
		Volume:           v.GetString("volume"),
		Password:         v.GetString("password"),
		PasswordStdin:    v.GetBool("password-stdin"),
		RecoveryPassword: v.GetString("recovery-password"),
		Offset:           v.GetInt64("offset"),
	}

	switch opts.Output {
	case "text", "json":
	default:
		return usageErrorf("invalid --output %q: must be text or json", opts.Output)
	}

	if opts.PasswordStdin {
		password, err := readPasswordFromStdin()
		if err != nil {
			return fmt.Errorf("unable to read password from stdin: %w", err)
		}
		opts.Password = password
	}

	return nil
}

func readPasswordFromStdin() (string, error) {
	var password string
	if _, err := fmt.Fscanln(os.Stdin, &password); err != nil {
		return "", err
	}
	return password, nil
}

// exactArgs is like cobra.ExactArgs but returns a usage-coded error.
func exactArgs(n int, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return usageErrorf("expected %s (got %d arguments)", usage, len(args))
		}
		return nil
	}
}

// rangeArgs is like cobra.RangeArgs but returns a usage-coded error.
func rangeArgs(min, max int, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < min || len(args) > max {
			return usageErrorf("expected %s (got %d arguments)", usage, len(args))
		}
		return nil
	}
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitCodeFor(err)
	}
	return ExitOK
}
