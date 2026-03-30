package report

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/firebase/genkit/go/genkit"

	"github.com/Koopa0/koopa0.dev/internal/ai"
	"github.com/Koopa0/koopa0.dev/internal/notify"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// PendingTask is a convenience alias for task.PendingTask.
type PendingTask = task.PendingTask

// MorningOutput is the JSON output of the morning-brief flow.
type MorningOutput struct {
	Text string `json:"text"`
}

// Morning implements the morning-brief flow as a zero-LLM deterministic nudge.
// It computes overdue/today task counts and sends a short notification
// reminding the user to open Claude for full planning.
type Morning struct {
	gf       *ai.GenkitFlow
	tasks    *task.Store
	notifier notify.Notifier
	loc      *time.Location
	logger   *slog.Logger
}

// NewMorning returns a Morning flow.
// No AI model or token budget needed — this is a deterministic nudge.
func NewMorning(
	g *genkit.Genkit,
	tasks *task.Store,
	notifier notify.Notifier,
	loc *time.Location,
	logger *slog.Logger,
) *Morning {
	mb := &Morning{
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
func (mb *Morning) Name() string { return "morning-brief" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (mb *Morning) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return mb.gf.Run(ctx, input)
}

func (mb *Morning) run(ctx context.Context) (MorningOutput, error) { //nolint:unparam // error required by Genkit flow signature
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
		return MorningOutput{Text: text}, nil
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

	return MorningOutput{Text: text}, nil
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
