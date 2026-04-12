package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for reports.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a new Store using the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Create inserts a new report.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Report, error) {
	row, err := s.q.CreateReport(ctx, db.CreateReportParams{
		Source:       p.Source,
		InResponseTo: p.InResponseTo,
		Content:      p.Content,
		Metadata:     p.Metadata,
		ReportedDate: p.ReportedDate,
	})
	if err != nil {
		return nil, fmt.Errorf("creating report: %w", err)
	}
	return rowToReport(&row), nil
}

// ByID returns a single report by ID.
func (s *Store) ByID(ctx context.Context, id int64) (*Report, error) {
	row, err := s.q.ReportByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying report %d: %w", id, err)
	}
	return rowToReport(&row), nil
}

// RecentReports returns all reports, newest first.
func (s *Store) RecentReports(ctx context.Context) ([]Report, error) {
	rows, err := s.q.RecentReports(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying recent reports: %w", err)
	}
	result := make([]Report, len(rows))
	for i := range rows {
		result[i] = *rowToReport(&rows[i])
	}
	return result, nil
}

func rowToReport(r *db.Report) *Report {
	rpt := &Report{
		ID:           r.ID,
		Source:       r.Source,
		InResponseTo: r.InResponseTo,
		Content:      r.Content,
		ReportedDate: r.ReportedDate,
		CreatedAt:    r.CreatedAt,
	}
	if r.Metadata != nil {
		_ = json.Unmarshal(r.Metadata, &rpt.Metadata)
	}
	return rpt
}
