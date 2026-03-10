package budget

import "testing"

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		limit   int64
		used    int64
		check   int64
		wantErr bool
	}{
		{name: "within budget", limit: 1000, used: 0, check: 500},
		{name: "exact limit", limit: 1000, used: 500, check: 500},
		{name: "over budget", limit: 1000, used: 500, check: 501, wantErr: true},
		{name: "already at limit", limit: 1000, used: 1000, check: 1, wantErr: true},
		{name: "zero check", limit: 1000, used: 999, check: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := New(tt.limit)
			b.Add(tt.used)
			err := b.Check(tt.check)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Check(%d) unexpected error: %v", tt.check, err)
			}
		})
	}
}

func TestAddAndUsed(t *testing.T) {
	b := New(10000)
	if got := b.Used(); got != 0 {
		t.Fatalf("Used() = %d, want 0", got)
	}
	b.Add(100)
	b.Add(200)
	if got := b.Used(); got != 300 {
		t.Fatalf("Used() = %d, want 300", got)
	}
}

func TestReset(t *testing.T) {
	b := New(10000)
	b.Add(5000)
	b.Reset()
	if got := b.Used(); got != 0 {
		t.Fatalf("Used() after Reset() = %d, want 0", got)
	}
	// should be able to use budget again after reset
	if err := b.Check(10000); err != nil {
		t.Fatalf("Check(10000) after Reset() unexpected error: %v", err)
	}
}
