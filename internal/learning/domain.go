package learning

import (
	"context"
	"fmt"

	"github.com/Koopa0/koopa/internal/db"
)

// CreateDomain inserts a new learning_domains row. Returns ErrConflict if the
// slug already exists (unique violation). Caller is responsible for format
// validation — the DB CHECK enforces `^[a-z][a-z0-9-]*$` but returning a
// generic constraint error loses context.
func (s *Store) CreateDomain(ctx context.Context, slug, name string) (*Domain, error) {
	row, err := s.q.CreateLearningDomain(ctx, db.CreateLearningDomainParams{
		Slug: slug,
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("creating learning domain %q: %w", slug, err)
	}
	return &Domain{
		Slug:      row.Slug,
		Name:      row.Name,
		Active:    row.Active,
		CreatedAt: row.CreatedAt,
	}, nil
}

// DomainExists reports whether a learning_domains row with the given slug
// exists. Used by propose_commitment(type=learning_domain) to reject
// duplicates before the INSERT fires a unique-violation round trip.
func (s *Store) DomainExists(ctx context.Context, slug string) (bool, error) {
	exists, err := s.q.LearningDomainExists(ctx, slug)
	if err != nil {
		return false, fmt.Errorf("checking learning domain %q: %w", slug, err)
	}
	return exists, nil
}

// Domains returns every active learning domain, slug-ordered.
func (s *Store) Domains(ctx context.Context) ([]Domain, error) {
	rows, err := s.q.ListLearningDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing learning domains: %w", err)
	}
	out := make([]Domain, len(rows))
	for i, r := range rows {
		out[i] = Domain{
			Slug:      r.Slug,
			Name:      r.Name,
			Active:    r.Active,
			CreatedAt: r.CreatedAt,
		}
	}
	return out, nil
}
