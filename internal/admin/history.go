package admin

// The consolidation/history endpoints were removed in the coordination
// rebuild. See docs/architecture/coordination-rebuild-progress.md and
// internal/weekly for the replacement — weekly review is now an
// on-demand Compute over primary state, matching the daily pattern.
//
// If a retrospective history viewer is ever wanted again, it should
// iterate past week starts and call weekly.Compute for each — no
// storage table required.
