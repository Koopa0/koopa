package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/firebase/genkit/go/genkit"
)

// TaskQuerier queries pending tasks from the local database.
// Data freshness depends on the hourly Notion sync (SyncAll).
// Staleness window: ≤1 hour. If Notion is unreachable, tasks degrade gracefully
// with stale data rather than failing outright.
type TaskQuerier interface {
	PendingTasks(ctx context.Context) ([]PendingTask, error)
}

// PublishedCounter counts published content since a given time.
type PublishedCounter interface {
	PublishedContentCountSince(ctx context.Context, since time.Time) (int64, error)
}

// Sender sends a text notification.
type Sender interface {
	Send(ctx context.Context, text string) error
}

// PendingTask represents a task pending completion.
type PendingTask struct {
	Title string
	Due   string // YYYY-MM-DD or empty
}

// MorningBriefOutput is the JSON output of the morning-brief flow.
type MorningBriefOutput struct {
	Text string `json:"text"`
}

// MorningBrief implements the morning-brief flow as a zero-LLM deterministic nudge.
// It computes overdue/today task counts and sends a short notification
// reminding the user to open Claude for full planning.
type MorningBrief struct {
	gf       *genkitFlow
	tasks    TaskQuerier
	notifier Sender
	loc      *time.Location
	logger   *slog.Logger
}

// NewMorningBrief returns a MorningBrief flow.
// No AI model or token budget needed — this is a deterministic nudge.
func NewMorningBrief(
	g *genkit.Genkit,
	tasks TaskQuerier,
	notifier Sender,
	loc *time.Location,
	logger *slog.Logger,
) *MorningBrief {
	mb := &MorningBrief{
		tasks:    tasks,
		notifier: notifier,
		loc:      loc,
		logger:   logger,
	}
	mb.gf = genkit.DefineFlow(g, "morning-brief", func(ctx context.Context, _ json.RawMessage) (json.RawMessage, error) {
		out, err := mb.run(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return mb
}

// Name returns the flow name for registry lookup.
func (mb *MorningBrief) Name() string { return "morning-brief" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (mb *MorningBrief) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return mb.gf.Run(ctx, input)
}

func (mb *MorningBrief) run(ctx context.Context) (MorningBriefOutput, error) { //nolint:unparam // error required by Genkit flow signature
	mb.logger.Info("morning-brief starting")

	now := time.Now().In(mb.loc)
	today := now.Format(time.DateOnly)

	tasks, err := mb.tasks.PendingTasks(ctx)
	if err != nil {
		mb.logger.Error("morning-brief: pending tasks", "error", err)
		// degrade: send a minimal nudge without task data
		text := buildNudge(now, 0, 0, 0, nil)
		if sendErr := mb.notifier.Send(ctx, text); sendErr != nil {
			mb.logger.Error("sending morning brief notification", "error", sendErr)
		}
		return MorningBriefOutput{Text: text}, nil
	}

	var total, overdueCount, todayCount int
	var severelyOverdue []string // tasks overdue > 3 days
	for _, t := range tasks {
		total++
		if t.Due == "" {
			continue
		}
		due, parseErr := time.Parse(time.DateOnly, t.Due)
		if parseErr != nil {
			continue
		}
		daysOverdue := int(now.Sub(due).Hours() / 24)
		switch {
		case t.Due == today:
			todayCount++
		case daysOverdue > 0:
			overdueCount++
			if daysOverdue > 3 {
				severelyOverdue = append(severelyOverdue, fmt.Sprintf("• %s（逾期 %d 天）", t.Title, daysOverdue))
			}
		}
	}

	text := buildNudge(now, total, overdueCount, todayCount, severelyOverdue)

	if err := mb.notifier.Send(ctx, text); err != nil {
		mb.logger.Error("sending morning brief notification", "error", err)
	}

	mb.logger.Info("morning-brief complete",
		"total", total,
		"overdue", overdueCount,
		"today", todayCount,
	)

	return MorningBriefOutput{Text: text}, nil
}

// buildNudge constructs a deterministic morning nudge message.
func buildNudge(now time.Time, total, overdue, today int, severelyOverdue []string) string {
	weekday := [...]string{"日", "一", "二", "三", "四", "五", "六"}[now.Weekday()]

	var b strings.Builder
	fmt.Fprintf(&b, "📋 早安！今天是 %s（%s）\n", now.Format("2006-01-02"), weekday)

	if total == 0 {
		b.WriteString("目前沒有待辦事項\n")
	} else {
		fmt.Fprintf(&b, "待辦：%d 件待完成", total)
		if overdue > 0 {
			fmt.Fprintf(&b, "（%d 件逾期）", overdue)
		}
		b.WriteByte('\n')

		if today > 0 {
			fmt.Fprintf(&b, "今日到期：%d 件\n", today)
		}
	}

	if len(severelyOverdue) > 0 {
		b.WriteString("\n⚠️ 嚴重逾期：\n")
		b.WriteString(strings.Join(severelyOverdue, "\n"))
		b.WriteByte('\n')
	}

	b.WriteString("\n👉 打開 Claude 做今日規劃")

	return b.String()
}

// NewMockMorningBrief returns a mock Flow for MOCK_MODE.
func NewMockMorningBrief() Flow {
	return &mockFlow{
		name:   "morning-brief",
		output: MorningBriefOutput{Text: "Mock morning brief"},
	}
}
