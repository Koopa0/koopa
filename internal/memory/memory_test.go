package memory

import (
	"math"
	"testing"
	"time"
)

func TestCategoryValid(t *testing.T) {
	tests := []struct {
		name     string
		category Category
		want     bool
	}{
		{name: "identity", category: CategoryIdentity, want: true},
		{name: "contextual", category: CategoryContextual, want: true},
		{name: "preference", category: CategoryPreference, want: true},
		{name: "project", category: CategoryProject, want: true},
		{name: "empty", category: "", want: false},
		{name: "unknown", category: "unknown", want: false},
		{name: "case mismatch", category: "Identity", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.category.Valid()
			if got != tt.want {
				t.Errorf("Category(%q).Valid() = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestCategoryDefaultTTL(t *testing.T) {
	tests := []struct {
		name     string
		category Category
		want     time.Duration
	}{
		{name: "identity never expires", category: CategoryIdentity, want: 0},
		{name: "preference 90d", category: CategoryPreference, want: 90 * 24 * time.Hour},
		{name: "project 60d", category: CategoryProject, want: 60 * 24 * time.Hour},
		{name: "contextual 30d", category: CategoryContextual, want: 30 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.category.DefaultTTL()
			if got != tt.want {
				t.Errorf("Category(%q).DefaultTTL() = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestCategoryDecayLambda(t *testing.T) {
	t.Run("identity returns zero", func(t *testing.T) {
		got := CategoryIdentity.DecayLambda()
		if got != 0 {
			t.Errorf("CategoryIdentity.DecayLambda() = %v, want 0", got)
		}
	})

	t.Run("contextual positive", func(t *testing.T) {
		got := CategoryContextual.DecayLambda()
		if got <= 0 {
			t.Errorf("CategoryContextual.DecayLambda() = %v, want > 0", got)
		}
		// Contextual half-life = 15d = 360h, lambda = ln(2)/360 ~ 0.001925
		want := math.Log(2) / (30 * 24 / 2)
		if math.Abs(got-want) > 1e-10 {
			t.Errorf("CategoryContextual.DecayLambda() = %v, want %v", got, want)
		}
	})

	t.Run("preference has slower decay than contextual", func(t *testing.T) {
		pref := CategoryPreference.DecayLambda()
		ctx := CategoryContextual.DecayLambda()
		if pref >= ctx {
			t.Errorf("preference lambda (%v) should be less than contextual (%v)", pref, ctx)
		}
	})

	t.Run("project between preference and contextual", func(t *testing.T) {
		proj := CategoryProject.DecayLambda()
		pref := CategoryPreference.DecayLambda()
		ctx := CategoryContextual.DecayLambda()
		if proj <= pref || proj >= ctx {
			t.Errorf("project lambda (%v) should be between preference (%v) and contextual (%v)", proj, pref, ctx)
		}
	})
}

func TestAllCategories(t *testing.T) {
	cats := AllCategories()
	if len(cats) != 4 {
		t.Fatalf("AllCategories() len = %d, want 4", len(cats))
	}
	for _, c := range cats {
		if !c.Valid() {
			t.Errorf("AllCategories() contains invalid category %q", c)
		}
	}
	// Identity must be first (highest priority).
	if cats[0] != CategoryIdentity {
		t.Errorf("AllCategories()[0] = %q, want %q", cats[0], CategoryIdentity)
	}
}

func TestConstants(t *testing.T) {
	if AutoMergeThreshold < 0.9 || AutoMergeThreshold > 1.0 {
		t.Errorf("AutoMergeThreshold = %v, want 0.9..1.0", AutoMergeThreshold)
	}
	if ArbitrationThreshold < 0.7 || ArbitrationThreshold > AutoMergeThreshold {
		t.Errorf("ArbitrationThreshold = %v, want 0.7..%v", ArbitrationThreshold, AutoMergeThreshold)
	}
	if MaxContentLength <= 0 {
		t.Errorf("MaxContentLength = %d, want > 0", MaxContentLength)
	}
	if MaxPerUser <= 0 {
		t.Errorf("MaxPerUser = %d, want > 0", MaxPerUser)
	}
	if EmbedTimeout <= 0 {
		t.Errorf("EmbedTimeout = %v, want > 0", EmbedTimeout)
	}
	if DecayInterval <= 0 {
		t.Errorf("DecayInterval = %v, want > 0", DecayInterval)
	}
	if MaxSearchQueryLen <= 0 {
		t.Errorf("MaxSearchQueryLen = %d, want > 0", MaxSearchQueryLen)
	}

	// Search weights must sum to 1.0.
	sum := searchWeightVector + searchWeightText + searchWeightDecay
	if math.Abs(sum-1.0) > 1e-10 {
		t.Errorf("search weights sum = %v, want 1.0", sum)
	}
}

func TestDecayScore(t *testing.T) {
	lambda := CategoryContextual.DecayLambda()

	t.Run("zero elapsed", func(t *testing.T) {
		got := decayScore(lambda, 0)
		if got != 1.0 {
			t.Errorf("decayScore(lambda, 0) = %v, want 1.0", got)
		}
	})

	t.Run("at half-life score is 0.5", func(t *testing.T) {
		halfLife := CategoryContextual.DefaultTTL() / 2
		got := decayScore(lambda, halfLife)
		if math.Abs(got-0.5) > 0.01 {
			t.Errorf("decayScore(lambda, halfLife) = %v, want ~0.5", got)
		}
	})

	t.Run("identity never decays", func(t *testing.T) {
		got := decayScore(0, 1000*time.Hour)
		if got != 1.0 {
			t.Errorf("decayScore(0, 1000h) = %v, want 1.0", got)
		}
	})

	t.Run("large elapsed approaches zero", func(t *testing.T) {
		got := decayScore(lambda, 10000*time.Hour)
		if got > 0.01 {
			t.Errorf("decayScore(lambda, 10000h) = %v, want < 0.01", got)
		}
	})
}

func TestParseExpiresIn(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "empty string", input: "", want: 0},
		{name: "7 days", input: "7d", want: 7 * 24 * time.Hour},
		{name: "30 days", input: "30d", want: 30 * 24 * time.Hour},
		{name: "90 days", input: "90d", want: 90 * 24 * time.Hour},
		{name: "24 hours", input: "24h", want: 24 * time.Hour},
		{name: "60 minutes", input: "60m", want: 60 * time.Minute},
		{name: "365 days at cap", input: "365d", want: 365 * 24 * time.Hour},
		{name: "exceeds 365d cap", input: "400d", want: 365 * 24 * time.Hour},
		{name: "invalid format", input: "abc", wantErr: true},
		{name: "no unit", input: "30", wantErr: true},
		{name: "negative", input: "-7d", wantErr: true},
		{name: "zero days", input: "0d", wantErr: true},
		{name: "float", input: "7.5d", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExpiresIn(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseExpiresIn(%q) = %v, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExpiresIn(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseExpiresIn(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveImportance(t *testing.T) {
	tests := []struct {
		name  string
		input int
		want  int
	}{
		{name: "zero defaults to 5", input: 0, want: 5},
		{name: "negative defaults to 5", input: -1, want: 5},
		{name: "above 10 defaults to 5", input: 11, want: 5},
		{name: "min valid", input: 1, want: 1},
		{name: "max valid", input: 10, want: 10},
		{name: "mid value", input: 7, want: 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveImportance(tt.input)
			if got != tt.want {
				t.Errorf("resolveImportance(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestCategoryExpiresAt(t *testing.T) {
	t.Run("identity returns nil", func(t *testing.T) {
		got := CategoryIdentity.ExpiresAt()
		if got != nil {
			t.Errorf("CategoryIdentity.ExpiresAt() = %v, want nil", got)
		}
	})

	t.Run("contextual returns future time", func(t *testing.T) {
		before := time.Now()
		got := CategoryContextual.ExpiresAt()
		if got == nil {
			t.Fatal("CategoryContextual.ExpiresAt() = nil, want non-nil")
		}
		want := before.Add(30 * 24 * time.Hour)
		// Allow 1 second tolerance.
		if got.Before(want.Add(-time.Second)) || got.After(want.Add(time.Second)) {
			t.Errorf("CategoryContextual.ExpiresAt() = %v, want ~%v", got, want)
		}
	})
}
