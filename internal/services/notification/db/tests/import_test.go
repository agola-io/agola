package tests

import (
	"testing"

	"agola.io/agola/internal/testutil"
)

func TestImportExport(t *testing.T) {
	log := testutil.NewLogger(t)

	seqs := map[string]uint64{
		"runwebhookdelivery_sequence_seq":   20,
		"commitstatusdelivery_sequence_seq": 20,
	}

	testutil.TestImportExport(t, "import.jsonc", newSetupDBFn(log), seqs)
}
