// Copyright 2026 Koopa. All rights reserved.

package content

import (
	"strings"
	"testing"
)

func TestCheckFieldLengths(t *testing.T) {
	atTitle := strings.Repeat("x", MaxTitleLen)
	overTitle := strings.Repeat("x", MaxTitleLen+1)
	multibyteAtTitle := strings.Repeat("中", MaxTitleLen)     // 300 runes, 900 bytes — under the rune cap
	multibyteOverTitle := strings.Repeat("中", MaxTitleLen+1) // 301 runes — over
	overExcerpt := strings.Repeat("x", MaxExcerptLen+1)
	atBody := strings.Repeat("x", MaxBodyBytes)
	overBody := strings.Repeat("x", MaxBodyBytes+1)

	tests := []struct {
		name    string
		title   *string
		excerpt *string
		body    *string
		wantErr string
	}{
		{name: "all nil"},
		{name: "title at cap", title: &atTitle},
		{name: "title over cap", title: &overTitle, wantErr: "title too long"},
		{name: "title multibyte at rune cap", title: &multibyteAtTitle},
		{name: "title multibyte over rune cap", title: &multibyteOverTitle, wantErr: "title too long"},
		{name: "excerpt over cap", excerpt: &overExcerpt, wantErr: "excerpt too long"},
		{name: "body at cap", body: &atBody},
		{name: "body over cap", body: &overBody, wantErr: "body too long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckFieldLengths(tt.title, tt.excerpt, tt.body)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("CheckFieldLengths() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("CheckFieldLengths() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckReviewNoteLength(t *testing.T) {
	if err := CheckReviewNoteLength(strings.Repeat("x", MaxReviewNoteLen)); err != nil {
		t.Errorf("CheckReviewNoteLength(at cap) = %v, want nil", err)
	}
	if err := CheckReviewNoteLength(strings.Repeat("x", MaxReviewNoteLen+1)); err == nil {
		t.Error("CheckReviewNoteLength(over cap) = nil, want error")
	}
}
