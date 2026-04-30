package ops

// since marks the project-wide baseline version for all tools shipped with
// the initial MCP surface. New tools added later should carry their own
// Since literal.
const since = "1.0.0"

// Catalog accessor design
// -----------------------
// Each tool is exposed as a package-level function returning a fresh
// Meta value. The catalog has no mutable package-level state: callers
// receive a copy, cannot mutate the source, and the compiler enforces
// named references so a typo fails to build.
//
// The trade-off is that every accessor call allocates a ~96-byte Meta.
// All tool registration happens once at NewServer time and the admin
// metadata endpoint runs well under a QPS — the allocation cost is
// irrelevant in both paths and not worth a global-state optimisation.

// MorningContext returns metadata for the morning planning query.
func MorningContext() Meta {
	return Meta{
		Name:        "morning_context",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Single-call daily-planning briefing: overdue tasks, today's tasks, committed daily plan items, upcoming tasks, active goals, pending directives, unverified hypotheses, recent RSS items from feeds tagged priority=high (NOT relevance-ranked despite the rss_highlights field name — for ranked retrieval use search_knowledge), plan history, content pipeline. Scope is today (not since-last-session). For mid-day catch-up after a break, use session_delta instead. For week-level retrospective, use weekly_summary.",
	}
}

// ReflectionContext returns metadata for the evening reflection query.
func ReflectionContext() Meta {
	return Meta{
		Name:        "reflection_context",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "End-of-day retrospective: plan vs actual completion, daily plan item outcomes, today's agent notes. Day-level scope (today only) — for week-level retrospective use weekly_summary; for since-last-session activity use session_delta.",
	}
}

// SearchKnowledge returns metadata for the cross-content search tool.
func SearchKnowledge() Meta {
	return Meta{
		Name:        "search_knowledge",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Search across all content types: articles, build logs, TILs, notes. Filters: content_type, project, date range. Use when looking for past knowledge or content.",
	}
}

// CaptureInbox returns metadata for the GTD inbox capture tool.
// FieldEnums advertises the energy enum structurally so callers do not
// have to discover the closed value set by trial-and-error.
func CaptureInbox() Meta {
	return Meta{
		Name:        "capture_inbox",
		Domain:      DomainDaily,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Quick task capture to inbox. Only title is required. Status is always inbox. Use when the user says 'add a task', 'remind me to', or expresses a concrete work item to capture.",
		FieldEnums: map[string][]string{
			"energy": {"high", "medium", "low"},
		},
	}
}

// AdvanceWork returns metadata for the GTD task lifecycle transitions.
// FieldEnums advertises the action / priority / energy enums
// structurally — they are closed value sets enforced by the handler,
// and surfacing them in tools/list saves callers a 422 round-trip.
func AdvanceWork() Meta {
	return Meta{
		Name:        "advance_work",
		Domain:      DomainDaily,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Personal-todo state transitions. Actions: clarify (inbox→todo, supply project/due/priority/energy to make it actionable; required before plan_day will accept the todo), start (todo→in_progress), complete (→done; if the todo is on today's daily plan, the matching plan_item is auto-marked done in the same transaction; recurring todos are auto-reset to next due date), defer (→someday).",
		FieldEnums: map[string][]string{
			"action":   {"clarify", "start", "complete", "defer"},
			"priority": {"high", "medium", "low"},
			"energy":   {"high", "medium", "low"},
		},
	}
}

// PlanDay returns metadata for the daily plan commit tool.
func PlanDay() Meta {
	return Meta{
		Name:        "plan_day",
		Domain:      DomainDaily,
		Writability: Idempotent,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Set the day's plan as one atomic replacement. Each todo MUST already be in state=todo (inbox/done/someday rejected — promote inbox via advance_work(action=clarify) first). The items list MUST be non-empty; to leave the day unplanned, do not call plan_day at all. The whole call (delete-existing + insert-new) runs in one transaction, so any per-item validation failure rolls back to the previous plan. items_removed reports todos that were in the previous plan but are NOT in the new list (true displacements only — todos carried over with the same task_id are not reported as removed even though their plan_item row gets a new id).",
	}
}

// WriteAgentNote returns metadata for the agent-note writer.
func WriteAgentNote() Meta {
	return Meta{
		Name:        "write_agent_note",
		Domain:      DomainMeta,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Create an agent note. Kind: plan (daily plan reasoning), context (session state snapshot), reflection (retrospective review). Use for session logging and reflection.",
	}
}

// QueryAgentNotes returns metadata for the agent-note reader.
func QueryAgentNotes() Meta {
	return Meta{
		Name:        "query_agent_notes",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Recall prior agent notes across date ranges. Filters: kind (plan|context|reflection), since/until (YYYY-MM-DD, default last 90 days), author. Use when conversation context no longer contains a note you wrote earlier — session reflections, plan reasoning, context snapshots. Ordered newest-first.",
	}
}

// ProposeGoal returns metadata for the flat propose_goal tool.
func ProposeGoal() Meta {
	return Meta{
		Name:        "propose_goal",
		Domain:      DomainMeta,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "Propose a goal (quarterly or multi-quarter commitment, optionally scoped to an area and given a target deadline). Returns a preview + signed proposal token — does NOT write to the database. Requires commit_proposal to finalize.",
	}
}

// ProposeProject returns metadata for the flat propose_project tool.
func ProposeProject() Meta {
	return Meta{
		Name:        "propose_project",
		Domain:      DomainMeta,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "Propose a project (concrete work unit that can be linked to a goal and an area). Returns a preview + signed proposal token — does NOT write to the database. Requires commit_proposal to finalize.",
	}
}

// ProposeMilestone returns metadata for the flat propose_milestone tool.
func ProposeMilestone() Meta {
	return Meta{
		Name:        "propose_milestone",
		Domain:      DomainMeta,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "Propose a milestone (progress marker scoped to a parent goal, with an optional target deadline). Returns a preview + signed proposal token — does NOT write to the database. Requires commit_proposal to finalize.",
	}
}

// ProposeDirective returns metadata for the flat propose_directive tool.
// FieldEnums advertises the priority enum structurally.
func ProposeDirective() Meta {
	return Meta{
		Name:        "propose_directive",
		Domain:      DomainMeta,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "Propose a directive (inter-agent work request targeting a named agent, carrying an a2a.Part array as request_parts). The first request_part MUST be a text part — its text becomes the directive title (server extracts up to 200 runes; data-only first parts are rejected at propose time). Returns a preview + signed proposal token — does NOT write to the database. Requires commit_proposal to finalize. Capability pre-check (SubmitTasks) runs at propose time; unauthorized callers fail fast without producing a signed token.",
		FieldEnums: map[string][]string{
			"priority": {"high", "medium", "low"},
		},
	}
}

// ProposeHypothesis returns metadata for the flat propose_hypothesis tool.
func ProposeHypothesis() Meta {
	return Meta{
		Name:        "propose_hypothesis",
		Domain:      DomainMeta,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "Propose a hypothesis (falsifiable claim with an invalidation condition and narrative content). Returns a preview + signed proposal token — does NOT write to the database. Requires commit_proposal to finalize. Per mcp-decision-policy §4, hypotheses must carry a concrete invalidation_condition; narrative reflections without a falsifiable claim belong in write_agent_note(kind=reflection) instead.",
	}
}

// ProposeLearningPlan returns metadata for the flat propose_learning_plan tool.
func ProposeLearningPlan() Meta {
	return Meta{
		Name:        "propose_learning_plan",
		Domain:      DomainMeta,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "Propose a learning plan (committed curriculum with a title + domain + optional parent goal). Returns a preview + signed proposal token — does NOT write to the database. Requires commit_proposal to finalize. Plan entries are added via manage_plan after the plan commits.",
	}
}

// ProposeLearningDomain returns metadata for the flat propose_learning_domain tool.
func ProposeLearningDomain() Meta {
	return Meta{
		Name:        "propose_learning_domain",
		Domain:      DomainMeta,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "Propose a learning domain (FK target for concepts/targets/sessions/plans — e.g. 'leetcode', 'japanese'). Returns a preview + signed proposal token — does NOT write to the database. Requires commit_proposal to finalize. Slug must match pattern ^[a-z][a-z0-9-]*$.",
	}
}

// CommitProposal returns metadata for the proposal-token commit tool.
func CommitProposal() Meta {
	return Meta{
		Name:        "commit_proposal",
		Domain:      DomainMeta,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Commit a previously proposed entity using the proposal_token from any propose_<type> tool. Creates the entity in the database. Supports optional modifications to override fields before commit.",
	}
}

// GoalProgress returns metadata for the active-goals query.
func GoalProgress() Meta {
	return Meta{
		Name:        "goal_progress",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Deep goal view: each active goal with its full milestone hierarchy (id/title/completed_at/target_deadline) AND its linked projects. This is the structural complement to morning_context.active_goals (which carries only the goal-summary level: title/area/quarter/deadline/milestone counts). Use goal_progress when you need milestone-level visibility or to see which projects are wired under a goal. For the daily briefing's headline counts, morning_context.active_goals is enough — calling both is redundant.",
	}
}

// FileReport returns metadata for the a2a artifact filing tool.
func FileReport() Meta {
	return Meta{
		Name:        "file_report",
		Domain:      DomainA2A,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "File a structured artifact. Two modes: (1) with in_response_to — completes the referenced task by attaching a response message and artifact, then transitions the task to completed; (2) without in_response_to — creates a standalone artifact attributed to the caller. Caller identity is resolved via the 'as' field. Requires PublishArtifacts capability.",
	}
}

// AcknowledgeDirective returns metadata for the task acknowledgement tool.
func AcknowledgeDirective() Meta {
	return Meta{
		Name:        "acknowledge_directive",
		Domain:      DomainA2A,
		Writability: Idempotent,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Mark a task as acknowledged by the calling agent. Validates the caller is the target. Use when the AI picks up a task during morning_context.",
	}
}

// TaskDetail returns metadata for the single-task read tool.
func TaskDetail() Meta {
	return Meta{
		Name:        "task_detail",
		Domain:      DomainA2A,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Fetch a single task with its full message history and artifacts. Caller must be the task source or target (else returns not_found — the tool does not leak the existence of tasks the caller is not party to). Use after submitting a directive to check whether the assignee accepted, replied, or completed it.",
	}
}

// TrackHypothesis returns metadata for the hypothesis lifecycle update tool.
func TrackHypothesis() Meta {
	return Meta{
		Name:        "track_hypothesis",
		Domain:      DomainMeta,
		Writability: Idempotent,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Update an existing hypothesis. Actions: verify (claim confirmed), invalidate (claim disproven), archive (retire), add_evidence (append supporting data). Hypothesis creation goes through propose_hypothesis.",
	}
}

// StartSession returns metadata for the learning session start tool.
func StartSession() Meta {
	return Meta{
		Name:        "start_session",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Begin a learning session. Required: domain (e.g. leetcode, japanese), mode (retrieval/practice/mixed/review/reading). Validates no other active session exists. Use when the user wants to start a learning/practice session.",
	}
}

// RecordAttempt returns metadata for the in-session attempt recorder.
// FieldEnums lists every accepted outcome value — both canonical DB
// enums (solved_independent, solved_with_hint, ...) and the semantic
// synonyms the coach is encouraged to type ("got it", "needed help",
// ...). Sourced from learning.mapProblemSolving + learning.mapImmersive;
// kept in sync by TestRecordAttemptEnumsCoverSynonyms.
func RecordAttempt() Meta {
	return Meta{
		Name:        "record_attempt",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Record an attempt within the active learning session. Accepts semantic outcomes ('got it', 'needed help', 'gave up') mapped to schema enums by session mode. Response echoes canonical_outcome alongside the input so the coach sees the normalized storage form. Auto-creates learning targets and concepts. Both high and low confidence observations are persisted; dashboard filters at read time. Observation constraint: severity is only valid for signal='weakness'; passing severity on mastery/improvement will reject the entire observation (check observation_warnings in response).",
		FieldEnums: map[string][]string{
			"outcome": {
				// Canonical DB-stored values.
				"solved_independent", "solved_with_hint", "solved_after_solution",
				"completed", "completed_with_support",
				"incomplete", "gave_up",
				// Semantic synonyms — problem_solving.
				"got it", "solved it", "nailed it",
				"needed help", "needed a hint", "got help",
				"saw answer", "saw the answer", "saw the answer first",
				"didn't finish", "not done",
				"gave up", "stuck",
				// Semantic synonyms — immersive (overlap with problem_solving
				// for shared outcomes; duplicates are acceptable in the enum
				// list since JSON Schema treats enum as a set).
				"finished", "done", "needed support",
			},
		},
	}
}

// EndSession returns metadata for the learning session terminator.
func EndSession() Meta {
	return Meta{
		Name:        "end_session",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "End the active learning session. Optional reflection text creates an agent note linked to the session. Returns session summary with all attempts.",
	}
}

// LearningDashboard returns metadata for the learning analytics dashboard.
// FieldEnums advertises the view + confidence_filter enums so tools/list
// callers see valid values structurally without parsing Description prose.
func LearningDashboard() Meta {
	return Meta{
		Name:        "learning_dashboard",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Learning analytics dashboard. Views: overview (sessions list), mastery (per-concept signal counts; mastery floor: <3 observations → always 'developing' regardless of signal distribution), weaknesses (cross-pattern weakness analysis by category+severity), retrieval (items with due <= now only; newly reviewed cards get future due dates and won't reappear until due), timeline (sessions with attempt stats by day), variations (problem relationship graph). Filter by domain and lookback period. Response shape is stable across views: {view, total, <view_key>: [...]} — the view-specific array is always present (empty [] on no data), other view keys are absent.",
		FieldEnums: map[string][]string{
			"view":              {"overview", "mastery", "weaknesses", "retrieval", "timeline", "variations"},
			"confidence_filter": {"high", "all"},
		},
	}
}

// RecommendNextTarget returns metadata for the session-scoped next-target
// recommender.
func RecommendNextTarget() Meta {
	return Meta{
		Name:        "recommend_next_target",
		Domain:      DomainLearning,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Recommend the next learning target during an active session. Combines weaknesses (concepts by severity × recency) with the variation graph (untried harder_variant / follow_up / same_pattern / similar_structure of problems the user already practiced on each weak concept). Interleaving filter operates on current session only — skips candidates whose anchor pattern was practiced in this session. Cross-session interleaving is the coach's job at session start via learning_dashboard view=timeline. Returns up to N candidates with source_concept + reason so the coach can explain the choice. When candidates are skipped, use recommended_by='tool' in the metadata of the resulting record_attempt to preserve the recommendation provenance.",
	}
}

// AttemptHistory returns metadata for the attempt lookup tool.
func AttemptHistory() Meta {
	return Meta{
		Name:        "attempt_history",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Read-side counterpart to record_attempt. Three lookup modes (exactly one required): target (title+domain — primary Improvement Verification Loop entry for 'how did this problem go last time'), concept_slug (returns attempts that observed the concept), session_id (returns all attempts for a past session, oldest first). Every returned attempt carries its full observations list (each with confidence label) and — on concept_slug mode — a matched_observation_id pointer into that list indicating which observation drove the query match. Observations within each attempt are ordered by coach-insertion (position ASC). Sort order: target/concept_slug DESC, session_id ASC. Empty result with resolved=false means the lookup target does not exist. Example (concept_slug, include_observations=false): {\"mode\":\"concept\",\"resolved\":true,\"attempts\":[{\"id\":\"...\",\"outcome\":\"solved_with_hint\",\"observations\":null,\"matched_observation_id\":\"obs-uuid\"}]} — matched_observation_id is still populated because the query did match an observation even though the list is skipped; pass include_observations=true (default) to see the observation itself.",
	}
}

// ManagePlan returns metadata for the learning plan lifecycle multiplexer.
func ManagePlan() Meta {
	return Meta{
		Name:        "manage_plan",
		Domain:      DomainLearning,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Learning plan lifecycle and entries. Actions: add_entries (accepts learning_target_id OR title for find-or-create using plan domain), remove_entries (draft only), update_entry (complete/skip/substitute), reorder, update_plan (activate/pause/complete/abandon), progress. The progress action returns aggregate counts plus a flat entry list with plan_entry_id, learning_target_id, title, position, status, phase — call it before update_entry to look up plan_entry_id.",
	}
}

// SessionProgress returns metadata for the in-session aggregate tool.
func SessionProgress() Meta {
	return Meta{
		Name:        "session_progress",
		Domain:      DomainLearning,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "In-session aggregate for the currently-active learning session: attempt count, elapsed time, paradigm distribution (problem_solving vs immersive with total minutes), concept slug distribution, and observation category (signal_type × category) distribution. Scope is the ACTIVE session only — when no session is active, returns {active: false, last_ended_session_id, last_ended_at} so the caller can pivot to attempt_history(session_id=...) for past-session review; this is an affordance, not a fallback, and aggregate fields are NOT populated for the ended session. Does NOT return concept kind distribution (pattern/skill/principle) because kind is currently auto-assigned to 'skill' for all session-created concepts; tracking would be trivial noise — see HERMES W-10 if kind discrimination becomes meaningful. paradigm_distribution is informational only — most sessions are single-paradigm by design, so do not infer mixing-ratio intent from a 0/N split. Distinct from session_delta, which is a 24h pan-feature snapshot (todos + agent notes + session count) not scoped to any learning_session.",
	}
}

// Content tools — flat per-intent design.
// 8 separate tools instead of one manage_content multiplexer. Rationale:
// actions have divergent input schemas + mixed authorization (publish is
// human-only); mapping one-intent-one-tool gives the LLM crisp tool
// selection and MCP annotations match the action (Destructive on
// publish/archive; read-only on list/read).

// CreateContent returns metadata for the create_content tool.
func CreateContent() Meta {
	return Meta{
		Name:        "create_content",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Create a new content row in status=draft. type is one of: article, essay, build-log, til, digest. Notes are NOT a content type — use create_note. Slug collisions surface as output.slug_conflict (caller can pick a new slug or switch to update_content).",
	}
}

// UpdateContent returns metadata for the update_content tool.
func UpdateContent() Meta {
	return Meta{
		Name:        "update_content",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Update editable fields on a content row. Any field may be omitted. Slug rename triggers slug_conflict path on collision. Does not change status — use submit_content_for_review / revert_content_to_draft / publish_content / archive_content for lifecycle transitions.",
	}
}

// SubmitContentForReview returns metadata for submit_content_for_review.
func SubmitContentForReview() Meta {
	return Meta{
		Name:        "submit_content_for_review",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Transition a draft content row to status=review. The Claude → human publish handoff signal: content is done on Claude's side and awaits human publish or revert.",
	}
}

// RevertContentToDraft returns metadata for revert_content_to_draft.
func RevertContentToDraft() Meta {
	return Meta{
		Name:        "revert_content_to_draft",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Transition a review content row back to status=draft. Use when the draft needs more work after it was submitted for review.",
	}
}

// PublishContent returns metadata for publish_content. Human-only.
func PublishContent() Meta {
	return Meta{
		Name:        "publish_content",
		Domain:      DomainContent,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "HUMAN-ONLY. Publish a review content row: status='published', is_public=true, published_at=now(). Requires explicit `as` field + registry Platform='human' — the server default does NOT confer publish authority.",
	}
}

// ArchiveContent returns metadata for archive_content.
func ArchiveContent() Meta {
	return Meta{
		Name:        "archive_content",
		Domain:      DomainContent,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Archive a content row (any state → archived). Terminal soft-delete; use for content that shouldn't appear in listings but whose audit trail must survive.",
	}
}

// ListContent returns metadata for list_content.
func ListContent() Meta {
	return Meta{
		Name:        "list_content",
		Domain:      DomainContent,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "List content rows with optional filters (type, status, project). Returns summaries — use read_content for the full body.",
	}
}

// ReadContent returns metadata for read_content.
func ReadContent() Meta {
	return Meta{
		Name:        "read_content",
		Domain:      DomainContent,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Fetch a single content row with full body by ID.",
	}
}

// Note tools — flat per-intent design. Three tools map 1:1 to user intent.

// CreateNote returns metadata for create_note.
func CreateNote() Meta {
	return Meta{
		Name:        "create_note",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Create a Zettelkasten note (notes table). kind one of: solve-note, concept-note, debug-postmortem, decision-log, reading-note, musing. Default maturity 'seed'. Notes are Koopa-private; no publication lifecycle.",
	}
}

// UpdateNote returns metadata for update_note.
func UpdateNote() Meta {
	return Meta{
		Name:        "update_note",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Update editable fields (slug / title / body / kind) on a note. Maturity transitions have their own tool (update_note_maturity) so state changes are auditable separately from content edits.",
	}
}

// UpdateNoteMaturity returns metadata for update_note_maturity.
func UpdateNoteMaturity() Meta {
	return Meta{
		Name:        "update_note_maturity",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Transition a note's maturity state. to_maturity one of: seed, stub, evergreen, needs_revision, archived. Any transition permitted (including recovery from archived).",
	}
}

// ManageFeeds returns metadata for the RSS feed subscription multiplexer.
//
// Writability is Destructive because the tool exposes update (enable/
// disable) and remove actions, both of which mutate or drop existing
// rows. Clients that respect DestructiveHint should confirm before
// dispatching these actions; list and add are overshadowed by the
// strongest action in the multiplexer.
func ManageFeeds() Meta {
	return Meta{
		Name:        "manage_feeds",
		Domain:      DomainContent,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Feed management: list, add (url+name), update (enable/disable), remove. Use for RSS feed subscription management.",
	}
}

// SystemStatus returns metadata for the pipeline health query.
func SystemStatus() Meta {
	return Meta{
		Name:        "system_status",
		Domain:      DomainSystem,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Snapshot of ingestion / pipeline / data health. Response sections: 'contents' = published-content counts by status and type; 'collected' = RSS feed_entries (total + by_status: unread/read/curated/ignored — a high 'unread' means RSS items haven't been triaged yet); 'feeds' = feed subscription health (total/enabled, auto-disabled feeds count against enabled); 'process_runs' = cron / pipeline run audit by kind (e.g. crawl, embed); 'projects' / 'notes' / 'activity' / 'tags' = catalog stats. Use when investigating ingestion or pipeline issues — for daily todo / goal data, morning_context covers it.",
	}
}

// SessionDelta returns metadata for the cross-session context bridge.
func SessionDelta() Meta {
	return Meta{
		Name:        "session_delta",
		Domain:      DomainSystem,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Activity snapshot since a point in time: todos created, todos completed, agent notes written, and learning session count. Returns what happened in the window (not a diff between two sessions, and not scoped to any learning_session). Default lookback: 24 hours. Use when reopening a session mid-day after a break — for the morning briefing call morning_context (today-scoped, broader sections) instead.",
	}
}

// WeeklySummary returns metadata for the week retrospective query.
func WeeklySummary() Meta {
	return Meta{
		Name:        "weekly_summary",
		Domain:      DomainSystem,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Week-level retrospective: todos completed, agent notes grouped by kind, learning session count and domains, concept mastery. Defaults to current week (Monday-Sunday). Use Monday for last week's review or any time you need cross-day patterns. For today only, use reflection_context. For since-last-session activity, use session_delta.",
	}
}

// All returns every tool meta in stable registration order. The order
// mirrors the addTool call sequence in internal/mcp/server.go and is
// enforced by TestOpsCatalogDrift. Adding a new tool requires appending
// an accessor here and registering a handler in the mcp package.
func All() []Meta {
	return []Meta{
		MorningContext(),
		ReflectionContext(),
		SearchKnowledge(),
		CaptureInbox(),
		AdvanceWork(),
		PlanDay(),
		WriteAgentNote(),
		QueryAgentNotes(),
		ProposeGoal(),
		ProposeProject(),
		ProposeMilestone(),
		ProposeDirective(),
		ProposeHypothesis(),
		ProposeLearningPlan(),
		ProposeLearningDomain(),
		CommitProposal(),
		GoalProgress(),
		FileReport(),
		AcknowledgeDirective(),
		TaskDetail(),
		TrackHypothesis(),
		StartSession(),
		RecordAttempt(),
		EndSession(),
		LearningDashboard(),
		RecommendNextTarget(),
		AttemptHistory(),
		ManagePlan(),
		SessionProgress(),
		CreateContent(),
		UpdateContent(),
		SubmitContentForReview(),
		RevertContentToDraft(),
		PublishContent(),
		ArchiveContent(),
		ListContent(),
		ReadContent(),
		CreateNote(),
		UpdateNote(),
		UpdateNoteMaturity(),
		ManageFeeds(),
		SystemStatus(),
		SessionDelta(),
		WeeklySummary(),
	}
}
