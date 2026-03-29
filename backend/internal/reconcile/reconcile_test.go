package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// --- fakes ---

type fakeDirectoryLister struct {
	slugs []string
	err   error
}

func (f *fakeDirectoryLister) ListDirectory(_ context.Context, _ string) ([]string, error) {
	return f.slugs, f.err
}

type fakeObsidianSlugLister struct {
	slugs []string
	err   error
}

func (f *fakeObsidianSlugLister) ObsidianContentSlugs(_ context.Context) ([]string, error) {
	return f.slugs, f.err
}

type fakeNotionPageIDLister struct {
	ids []string
	err error
}

func (f *fakeNotionPageIDLister) NotionPageIDs(_ context.Context) ([]string, error) {
	return f.ids, f.err
}

type fakeNotionDBQuerier struct {
	ids map[string][]string // databaseID → page IDs
	err error
}

func (f *fakeNotionDBQuerier) QueryPageIDs(_ context.Context, databaseID string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ids[databaseID], nil
}

type fakeSender struct {
	sent []string
	err  error
}

func (f *fakeSender) Send(_ context.Context, text string) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, text)
	return nil
}

type fakeRoleLookup struct {
	roles map[string]string // role → databaseID
	err   error
}

func (f *fakeRoleLookup) DatabaseIDByRole(_ context.Context, role string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	id, ok := f.roles[role]
	if !ok {
		return "", errors.New("role not found")
	}
	return id, nil
}

// discardLogger returns an slog.Logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newReconciler builds a Reconciler with the given fakes wired up.
// Constructs the struct directly (same package) since New() takes concrete types.
func newReconciler(
	gh directoryLister,
	cs obsidianSlugLister,
	ps notionPageIDLister,
	gs notionPageIDLister,
	ndb notionDBQuerier,
	s sender,
	rl roleLookup,
) *Reconciler {
	return &Reconciler{
		github:   gh,
		content:  cs,
		projects: ps,
		goals:    gs,
		notionDB: ndb,
		notifier: s,
		roles:    rl,
		logger:   discardLogger(),
	}
}

// --- diff ---

func TestDiff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		source       []string
		target       []string
		wantMissing  []string
		wantOrphaned []string
	}{
		{
			name:         "both empty",
			source:       nil,
			target:       nil,
			wantMissing:  nil,
			wantOrphaned: nil,
		},
		{
			name:         "perfect sync",
			source:       []string{"a", "b", "c"},
			target:       []string{"a", "b", "c"},
			wantMissing:  nil,
			wantOrphaned: nil,
		},
		{
			name:        "missing in target",
			source:      []string{"a", "b", "c"},
			target:      []string{"a"},
			wantMissing: []string{"b", "c"},
		},
		{
			name:         "orphaned in target",
			source:       []string{"a"},
			target:       []string{"a", "b", "c"},
			wantOrphaned: []string{"b", "c"},
		},
		{
			name:         "missing and orphaned",
			source:       []string{"a", "b"},
			target:       []string{"b", "c"},
			wantMissing:  []string{"a"},
			wantOrphaned: []string{"c"},
		},
		{
			name:        "source non-empty, target empty",
			source:      []string{"a", "b"},
			target:      nil,
			wantMissing: []string{"a", "b"},
		},
		{
			name:         "source empty, target non-empty",
			source:       nil,
			target:       []string{"a", "b"},
			wantOrphaned: []string{"a", "b"},
		},
		{
			name:         "single element match",
			source:       []string{"x"},
			target:       []string{"x"},
			wantMissing:  nil,
			wantOrphaned: nil,
		},
	}

	sortStrings := cmpopts.SortSlices(func(a, b string) bool { return a < b })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMissing, gotOrphaned := diff(tt.source, tt.target)

			if diff := cmp.Diff(tt.wantMissing, gotMissing, sortStrings, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("missing mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantOrphaned, gotOrphaned, sortStrings, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("orphaned mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- Report.HasIssues ---

func TestReportHasIssues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    Report
		want bool
	}{
		{
			name: "empty report has no issues",
			r:    Report{},
			want: false,
		},
		{
			name: "obsidian missing triggers issue",
			r:    Report{ObsidianMissing: []string{"slug-a"}},
			want: true,
		},
		{
			name: "obsidian orphaned triggers issue",
			r:    Report{ObsidianOrphaned: []string{"slug-b"}},
			want: true,
		},
		{
			name: "projects missing triggers issue",
			r:    Report{ProjectsMissing: []string{"page-1"}},
			want: true,
		},
		{
			name: "projects orphaned triggers issue",
			r:    Report{ProjectsOrphaned: []string{"page-2"}},
			want: true,
		},
		{
			name: "goals missing triggers issue",
			r:    Report{GoalsMissing: []string{"goal-1"}},
			want: true,
		},
		{
			name: "goals orphaned triggers issue",
			r:    Report{GoalsOrphaned: []string{"goal-2"}},
			want: true,
		},
		{
			name: "all fields populated is an issue",
			r: Report{
				ObsidianMissing:  []string{"a"},
				ObsidianOrphaned: []string{"b"},
				ProjectsMissing:  []string{"c"},
				ProjectsOrphaned: []string{"d"},
				GoalsMissing:     []string{"e"},
				GoalsOrphaned:    []string{"f"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.r.HasIssues()
			if got != tt.want {
				t.Errorf("HasIssues() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- formatReport ---

func TestFormatReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		r           Report
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "empty report has header only",
			r:           Report{},
			wantContain: []string{"[Reconciliation Report]"},
			wantAbsent:  []string{"GitHub", "Obsidian:", "Projects:", "Goals:"},
		},
		{
			name:        "obsidian missing shows plus lines",
			r:           Report{ObsidianMissing: []string{"post-a", "post-b"}},
			wantContain: []string{"Obsidian:", "2 files in GitHub but not in DB", "+ post-a", "+ post-b"},
		},
		{
			name:        "obsidian orphaned shows minus lines",
			r:           Report{ObsidianOrphaned: []string{"old-post"}},
			wantContain: []string{"Obsidian:", "1 records in DB but not in GitHub", "- old-post"},
		},
		{
			name:        "projects missing",
			r:           Report{ProjectsMissing: []string{"proj-id-1"}},
			wantContain: []string{"Projects:", "1 in Notion but not in DB", "+ proj-id-1"},
		},
		{
			name:        "goals orphaned",
			r:           Report{GoalsOrphaned: []string{"goal-id-1"}},
			wantContain: []string{"Goals:", "1 in DB but not in Notion", "- goal-id-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatReport(&tt.r)
			for _, sub := range tt.wantContain {
				if !strings.Contains(got, sub) {
					t.Errorf("formatReport() output missing %q\nfull output:\n%s", sub, got)
				}
			}
			for _, sub := range tt.wantAbsent {
				if strings.Contains(got, sub) {
					t.Errorf("formatReport() output should not contain %q\nfull output:\n%s", sub, got)
				}
			}
		})
	}
}

// --- ReconcileObsidian ---

func TestReconcileObsidian(t *testing.T) {
	t.Parallel()

	noopProjects := &fakeNotionPageIDLister{}
	noopGoals := &fakeNotionPageIDLister{}
	noopNotionDB := &fakeNotionDBQuerier{}
	noopRoles := &fakeRoleLookup{roles: map[string]string{}}

	tests := []struct {
		name        string
		github      *fakeDirectoryLister
		content     *fakeObsidianSlugLister
		sender      *fakeSender
		wantSent    bool // whether notifier.Send should be called
		wantErrSend bool // whether Send returns an error to propagate
	}{
		{
			name:     "no drift sends consistent summary",
			github:   &fakeDirectoryLister{slugs: []string{"post-a", "post-b"}},
			content:  &fakeObsidianSlugLister{slugs: []string{"post-a", "post-b"}},
			sender:   &fakeSender{},
			wantSent: true,
		},
		{
			name:     "empty sources sends consistent summary",
			github:   &fakeDirectoryLister{slugs: nil},
			content:  &fakeObsidianSlugLister{slugs: nil},
			sender:   &fakeSender{},
			wantSent: true,
		},
		{
			name:     "file in github missing from DB sends notification",
			github:   &fakeDirectoryLister{slugs: []string{"post-a", "post-b"}},
			content:  &fakeObsidianSlugLister{slugs: []string{"post-a"}},
			sender:   &fakeSender{},
			wantSent: true,
		},
		{
			name:     "record in DB missing from github sends notification",
			github:   &fakeDirectoryLister{slugs: []string{"post-a"}},
			content:  &fakeObsidianSlugLister{slugs: []string{"post-a", "ghost-post"}},
			sender:   &fakeSender{},
			wantSent: true,
		},
		{
			name:     "github error suppresses diff, sends consistent summary",
			github:   &fakeDirectoryLister{err: errors.New("github api down")},
			content:  &fakeObsidianSlugLister{slugs: []string{"post-a"}},
			sender:   &fakeSender{},
			wantSent: true,
		},
		{
			name:     "db error suppresses diff, sends consistent summary",
			github:   &fakeDirectoryLister{slugs: []string{"post-a"}},
			content:  &fakeObsidianSlugLister{err: errors.New("db unavailable")},
			sender:   &fakeSender{},
			wantSent: true,
		},
		{
			name:        "notification send failure is propagated",
			github:      &fakeDirectoryLister{slugs: []string{"post-a", "post-b"}},
			content:     &fakeObsidianSlugLister{slugs: []string{"post-a"}},
			sender:      &fakeSender{err: errors.New("telegram offline")},
			wantSent:    false,
			wantErrSend: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			r := newReconciler(tt.github, tt.content, noopProjects, noopGoals, noopNotionDB, tt.sender, noopRoles)
			err := r.ReconcileObsidian(ctx)

			if tt.wantErrSend {
				if err == nil {
					t.Fatal("expected error from Send, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ReconcileObsidian() unexpected error: %v", err)
			}

			sent := len(tt.sender.sent) > 0
			if sent != tt.wantSent {
				t.Errorf("notification sent = %v, want %v (messages: %v)", sent, tt.wantSent, tt.sender.sent)
			}
		})
	}
}

// --- ReconcileNotion ---

const (
	projDBID = "proj-db-id"
	goalDBID = "goal-db-id"
)

func defaultRoles() *fakeRoleLookup {
	return &fakeRoleLookup{roles: map[string]string{
		"projects": projDBID,
		"goals":    goalDBID,
	}}
}

func TestReconcileNotion(t *testing.T) {
	t.Parallel()

	noopGitHub := &fakeDirectoryLister{slugs: nil}
	noopContent := &fakeObsidianSlugLister{slugs: nil}

	tests := []struct {
		name        string
		projects    *fakeNotionPageIDLister
		goals       *fakeNotionPageIDLister
		notionDB    *fakeNotionDBQuerier
		roles       *fakeRoleLookup
		wantSent    bool
		wantErrSend bool
	}{
		{
			name:     "no drift sends consistent summary",
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1", "proj-2"}},
			goals:    &fakeNotionPageIDLister{ids: []string{"goal-1"}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {"proj-1", "proj-2"},
				goalDBID: {"goal-1"},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "project in notion missing from local DB",
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1"}},
			goals:    &fakeNotionPageIDLister{ids: []string{"goal-1"}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {"proj-1", "proj-2"},
				goalDBID: {"goal-1"},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "project in local DB orphaned (not in notion)",
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1", "ghost-proj"}},
			goals:    &fakeNotionPageIDLister{ids: []string{}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {"proj-1"},
				goalDBID: {"goal-1"},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "goal in notion missing from local DB",
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1"}},
			goals:    &fakeNotionPageIDLister{ids: []string{}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {"proj-1"},
				goalDBID: {"goal-1", "goal-2"},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "role lookup failure skips that domain, sends consistent summary",
			projects: &fakeNotionPageIDLister{ids: []string{}},
			goals:    &fakeNotionPageIDLister{ids: []string{}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{}},
			roles:    &fakeRoleLookup{err: errors.New("notion roles unavailable")},
			wantSent: true,
		},
		{
			name:     "local projects error suppresses projects diff, sends consistent summary",
			projects: &fakeNotionPageIDLister{err: errors.New("db down")},
			goals:    &fakeNotionPageIDLister{ids: []string{"goal-1"}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {"proj-1"},
				goalDBID: {"goal-1"},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "notion DB error suppresses projects diff, sends consistent summary",
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1"}},
			goals:    &fakeNotionPageIDLister{ids: []string{"goal-1"}},
			notionDB: &fakeNotionDBQuerier{err: errors.New("notion API down")},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "empty notion results skip diff, sends consistent summary",
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1", "proj-2"}},
			goals:    &fakeNotionPageIDLister{ids: []string{"goal-1"}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {},
				goalDBID: {},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			sender := &fakeSender{}

			r := newReconciler(noopGitHub, noopContent, tt.projects, tt.goals, tt.notionDB, sender, tt.roles)
			err := r.ReconcileNotion(ctx)

			if tt.wantErrSend {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ReconcileNotion() unexpected error: %v", err)
			}

			sent := len(sender.sent) > 0
			if sent != tt.wantSent {
				t.Errorf("notification sent = %v, want %v (messages: %v)", sent, tt.wantSent, sender.sent)
			}
		})
	}
}

// --- Run (full reconciliation) ---

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		github   *fakeDirectoryLister
		content  *fakeObsidianSlugLister
		projects *fakeNotionPageIDLister
		goals    *fakeNotionPageIDLister
		notionDB *fakeNotionDBQuerier
		roles    *fakeRoleLookup
		wantSent bool
	}{
		{
			name:     "fully synced sends consistent summary",
			github:   &fakeDirectoryLister{slugs: []string{"post-a"}},
			content:  &fakeObsidianSlugLister{slugs: []string{"post-a"}},
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1"}},
			goals:    &fakeNotionPageIDLister{ids: []string{"goal-1"}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {"proj-1"},
				goalDBID: {"goal-1"},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "obsidian drift triggers notification",
			github:   &fakeDirectoryLister{slugs: []string{"post-a", "post-b"}},
			content:  &fakeObsidianSlugLister{slugs: []string{"post-a"}},
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1"}},
			goals:    &fakeNotionPageIDLister{ids: []string{"goal-1"}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {"proj-1"},
				goalDBID: {"goal-1"},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "notion drift triggers notification",
			github:   &fakeDirectoryLister{slugs: []string{"post-a"}},
			content:  &fakeObsidianSlugLister{slugs: []string{"post-a"}},
			projects: &fakeNotionPageIDLister{ids: []string{"proj-1"}},
			goals:    &fakeNotionPageIDLister{ids: []string{}},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{
				projDBID: {"proj-1"},
				goalDBID: {"goal-1", "goal-2"},
			}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "all sources empty sends consistent summary",
			github:   &fakeDirectoryLister{slugs: nil},
			content:  &fakeObsidianSlugLister{slugs: nil},
			projects: &fakeNotionPageIDLister{ids: nil},
			goals:    &fakeNotionPageIDLister{ids: nil},
			notionDB: &fakeNotionDBQuerier{ids: map[string][]string{}},
			roles:    defaultRoles(),
			wantSent: true,
		},
		{
			name:     "all errors suppress all diffs, sends consistent summary",
			github:   &fakeDirectoryLister{err: errors.New("github down")},
			content:  &fakeObsidianSlugLister{err: errors.New("db down")},
			projects: &fakeNotionPageIDLister{err: errors.New("db down")},
			goals:    &fakeNotionPageIDLister{err: errors.New("db down")},
			notionDB: &fakeNotionDBQuerier{err: errors.New("notion down")},
			roles:    defaultRoles(),
			wantSent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			sender := &fakeSender{}

			r := newReconciler(tt.github, tt.content, tt.projects, tt.goals, tt.notionDB, sender, tt.roles)
			if err := r.Run(ctx); err != nil {
				t.Fatalf("Run() unexpected error: %v", err)
			}

			sent := len(sender.sent) > 0
			if sent != tt.wantSent {
				t.Errorf("notification sent = %v, want %v (messages: %v)", sent, tt.wantSent, sender.sent)
			}
		})
	}
}
