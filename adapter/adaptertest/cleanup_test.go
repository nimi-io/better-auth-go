package adaptertest

import (
	"errors"
	"reflect"
	"testing"
)

// Port of packages/test-utils/src/adapter/cleanup.test.ts

type testRow struct{ ID string }

func rowsOf(model string, ids ...string) ModelRows[testRow] {
	var m ModelRows[testRow]
	for _, id := range ids {
		m.Add(model, testRow{ID: id})
	}
	return m
}

func TestCleanupRows(t *testing.T) {
	t.Run("does not retry rows that were deleted successfully", func(t *testing.T) {
		var deleted []string
		tracked := rowsOf("user", "user-1", "user-2")
		cleanupRow := func(_ string, row testRow) (CleanupResult, error) {
			deleted = append(deleted, row.ID)
			return CleanupComplete, nil
		}
		tracked = CleanupRows(tracked, cleanupRow)
		tracked = CleanupRows(tracked, cleanupRow)
		if !reflect.DeepEqual(deleted, []string{"user-1", "user-2"}) {
			t.Fatalf("deleted = %v", deleted)
		}
		if tracked.Len() != 0 {
			t.Fatalf("tracked = %v, want empty", tracked)
		}
	})

	t.Run("retries only rows whose deletion failed", func(t *testing.T) {
		var attempted []string
		secondRowFails := true
		tracked := rowsOf("user", "user-1", "user-2", "user-3")
		cleanupRow := func(_ string, row testRow) (CleanupResult, error) {
			attempted = append(attempted, row.ID)
			if row.ID == "user-2" && secondRowFails {
				secondRowFails = false
				return "", errors.New("Temporary delete failure")
			}
			return CleanupComplete, nil
		}
		tracked = CleanupRows(tracked, cleanupRow)
		if want := rowsOf("user", "user-2"); !reflect.DeepEqual(tracked, want) {
			t.Fatalf("tracked = %v, want %v", tracked, want)
		}
		tracked = CleanupRows(tracked, cleanupRow)
		if !reflect.DeepEqual(attempted, []string{"user-1", "user-2", "user-3", "user-2"}) {
			t.Fatalf("attempted = %v", attempted)
		}
		if tracked.Len() != 0 {
			t.Fatalf("tracked = %v, want empty", tracked)
		}
	})

	t.Run("retains rows explicitly marked for retry", func(t *testing.T) {
		modelAvailable := false
		tracked := rowsOf("customModel", "custom-1")
		cleanupRow := func(string, testRow) (CleanupResult, error) {
			if modelAvailable {
				return CleanupComplete, nil
			}
			return CleanupRetry, nil
		}
		tracked = CleanupRows(tracked, cleanupRow)
		if want := rowsOf("customModel", "custom-1"); !reflect.DeepEqual(tracked, want) {
			t.Fatalf("tracked = %v, want %v", tracked, want)
		}
		modelAvailable = true
		tracked = CleanupRows(tracked, cleanupRow)
		if tracked.Len() != 0 {
			t.Fatalf("tracked = %v, want empty", tracked)
		}
	})
}
