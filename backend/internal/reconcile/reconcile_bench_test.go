package reconcile

import (
	"fmt"
	"testing"
)

func BenchmarkDiff_Small(b *testing.B) {
	source := []string{"a", "b", "c", "d", "e"}
	target := []string{"c", "d", "e", "f", "g"}
	b.ReportAllocs()
	for b.Loop() {
		diff(source, target)
	}
}

func BenchmarkDiff_Large(b *testing.B) {
	source := benchStrings("src-", 1000)
	target := benchStrings("tgt-", 1000)
	b.ReportAllocs()
	for b.Loop() {
		diff(source, target)
	}
}

func BenchmarkDiff_PerfectSync(b *testing.B) {
	items := benchStrings("item-", 500)
	b.ReportAllocs()
	for b.Loop() {
		diff(items, items)
	}
}

func BenchmarkHasIssues_Empty(b *testing.B) {
	r := Report{}
	b.ReportAllocs()
	for b.Loop() {
		r.HasIssues()
	}
}

func BenchmarkHasIssues_Populated(b *testing.B) {
	r := Report{
		ObsidianMissing:  []string{"a"},
		ProjectsMissing:  []string{"b"},
		GoalsMissing:     []string{"c"},
		ObsidianOrphaned: []string{"d"},
		ProjectsOrphaned: []string{"e"},
		GoalsOrphaned:    []string{"f"},
	}
	b.ReportAllocs()
	for b.Loop() {
		r.HasIssues()
	}
}

func BenchmarkFormatReport_Full(b *testing.B) {
	r := Report{
		ObsidianMissing:  benchStrings("obs-miss-", 10),
		ObsidianOrphaned: benchStrings("obs-orph-", 5),
		ProjectsMissing:  benchStrings("proj-miss-", 3),
		ProjectsOrphaned: benchStrings("proj-orph-", 2),
		GoalsMissing:     benchStrings("goal-miss-", 4),
		GoalsOrphaned:    benchStrings("goal-orph-", 1),
	}
	b.ReportAllocs()
	for b.Loop() {
		formatReport(&r)
	}
}

func benchStrings(prefix string, n int) []string {
	s := make([]string, n)
	for i := range n {
		s[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return s
}
