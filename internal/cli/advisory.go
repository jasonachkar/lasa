package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/jasonachkar/lasa/internal/advisory"
	"github.com/jasonachkar/lasa/internal/storage"
	"github.com/spf13/cobra"
)

func advisoryCommand() *cobra.Command {
	root := &cobra.Command{Use: "advisories", Short: "Manage local, offline package advisory databases"}
	var output, release string
	update := &cobra.Command{Use: "update", Short: "Fetch the official Debian tracker over verified HTTPS (explicit network operation)", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if output == "" {
			return failure("CONFIG_INVALID", "validate", "--output", fmt.Errorf("an explicit advisory output path is required"))
		}
		db, e := advisory.Debian(c.Context(), release)
		if e != nil {
			return failure("ADVISORY_UPDATE_FAILED", "fetch_official_debian_tracker", release, e)
		}
		raw, e := json.MarshalIndent(db, "", "  ")
		if e != nil {
			return e
		}
		if e = storage.Directory(filepath.Dir(output)); e != nil {
			return failure("OUTPUT_WRITE_FAILED", "create_advisory_directory", filepath.Dir(output), e)
		}
		if e = storage.Atomic(output, raw); e != nil {
			return failure("OUTPUT_WRITE_FAILED", "persist_advisories", output, e)
		}
		_, e = fmt.Fprintf(c.OutOrStdout(), "Saved %d vendor-derived advisory records for Debian %s to %s; expires %s. Source authenticity: verified HTTPS, no detached upstream signature.\n", len(db.Records), release, output, db.ExpiresAt.Format(time.RFC3339))
		return e
	}}
	update.Flags().StringVar(&release, "release", "", "exact Debian release codename, such as bookworm or trixie")
	update.Flags().StringVar(&output, "output", "", "private database output path (required)")
	var input, importOutput string
	importCommand := &cobra.Command{Use: "import", Short: "Validate and privately copy a vendor-derived lasa.advisories/v1 database", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if input == "" || importOutput == "" {
			return failure("CONFIG_INVALID", "validate", "advisory import", fmt.Errorf("--input and --output are required"))
		}
		raw, e := storage.Read(input, advisory.MaxBytes)
		if e != nil {
			return failure("ADVISORY_IMPORT_FAILED", "read_database", input, e)
		}
		db, e := advisory.Decode(raw)
		if e != nil {
			return failure("ADVISORY_IMPORT_FAILED", "validate_database", input, e)
		}
		if e = db.Fresh(time.Now(), 0); e != nil {
			return failure("ADVISORY_IMPORT_FAILED", "validate_database_freshness", input, e)
		}
		normalized, e := json.MarshalIndent(db, "", "  ")
		if e != nil {
			return e
		}
		if e = storage.Directory(filepath.Dir(importOutput)); e != nil {
			return failure("OUTPUT_WRITE_FAILED", "create_advisory_directory", filepath.Dir(importOutput), e)
		}
		if e = storage.Atomic(importOutput, normalized); e != nil {
			return failure("OUTPUT_WRITE_FAILED", "persist_advisories", importOutput, e)
		}
		_, e = fmt.Fprintf(c.OutOrStdout(), "Imported %d records to %s. Import validates structure and freshness; authenticate the vendor source independently.\n", len(db.Records), importOutput)
		return e
	}}
	importCommand.Flags().StringVar(&input, "input", "", "authenticated vendor-derived database")
	importCommand.Flags().StringVar(&importOutput, "output", "", "private database output path")
	root.AddCommand(update, importCommand)
	return root
}
