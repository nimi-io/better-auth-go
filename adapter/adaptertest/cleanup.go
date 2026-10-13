package adaptertest

// CleanupResult is the outcome of cleaning one row: CleanupComplete or CleanupRetry.
type CleanupResult string

// Cleanup results.
const (
	CleanupComplete CleanupResult = "complete"
	CleanupRetry    CleanupResult = "retry"
)

// ModelRows are tracked rows grouped by model. Models keeps the insertion order (object key
// order upstream).
type ModelRows[Row any] struct {
	Models []string
	Rows   map[string][]Row
}

// Add appends a row for model.
func (m *ModelRows[Row]) Add(model string, row Row) {
	if m.Rows == nil {
		m.Rows = map[string][]Row{}
	}
	if _, ok := m.Rows[model]; !ok {
		m.Models = append(m.Models, model)
	}
	m.Rows[model] = append(m.Rows[model], row)
}

// Len returns the number of models with tracked rows.
func (m ModelRows[Row]) Len() int { return len(m.Models) }

// CleanupRows runs cleanupRow for every tracked row and returns the rows that have to be
// retried: rows whose cleanup returned CleanupRetry or failed with an error (cleanupRows).
func CleanupRows[Row any](tracked ModelRows[Row], cleanupRow func(model string, row Row) (CleanupResult, error)) ModelRows[Row] {
	var retry ModelRows[Row]
	for _, model := range tracked.Models {
		var failed []Row
		for _, row := range tracked.Rows[model] {
			res, err := safeCleanup(cleanupRow, model, row)
			if err != nil || res == CleanupRetry {
				failed = append(failed, row)
			}
		}
		if len(failed) > 0 {
			for _, row := range failed {
				retry.Add(model, row)
			}
		}
	}
	return retry
}

// safeCleanup converts panics into errors (a thrown error is retried upstream).
func safeCleanup[Row any](fn func(string, Row) (CleanupResult, error), model string, row Row) (res CleanupResult, err error) {
	defer func() {
		if p := recover(); p != nil {
			res, err = CleanupRetry, errPanic{p}
		}
	}()
	return fn(model, row)
}

type errPanic struct{ v any }

func (e errPanic) Error() string { return "panic during cleanup" }
