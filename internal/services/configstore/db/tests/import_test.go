package tests

import (
	"testing"

	"agola.io/agola/internal/testutil"
)

func TestImportExport(t *testing.T) {
	log := testutil.NewLogger(t)

	seqs := map[string]uint64{}

	testutil.TestImportExport(t, "import.jsonc", newSetupDBFn(log), seqs)
}
