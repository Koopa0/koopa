package agent

import (
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHistory_Operations tests History struct operations
func TestHistory_Operations(t *testing.T) {
	t.Parallel()

	t.Run("new history is empty", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()
		assert.NotNil(t, h)
		assert.Equal(t, 0, h.Count())
		assert.Empty(t, h.Messages())
	})

	t.Run("add messages", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()

		h.Add("Hello", "Hi there!")
		assert.Equal(t, 2, h.Count()) // user + assistant

		msgs := h.Messages()
		require.Len(t, msgs, 2)
		assert.Equal(t, ai.RoleUser, msgs[0].Role)
		assert.Equal(t, ai.RoleModel, msgs[1].Role)
	})

	t.Run("add single message", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()

		sysMsg := &ai.Message{
			Role:    ai.RoleSystem,
			Content: []*ai.Part{ai.NewTextPart("System prompt")},
		}
		h.AddMessage(sysMsg)

		assert.Equal(t, 1, h.Count())
		assert.Equal(t, ai.RoleSystem, h.Messages()[0].Role)
	})

	t.Run("clear history", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()
		h.Add("Test", "Response")

		assert.Equal(t, 2, h.Count())

		h.Clear()
		assert.Equal(t, 0, h.Count())
		assert.Empty(t, h.Messages())
	})

	t.Run("create from existing messages", func(t *testing.T) {
		t.Parallel()
		msgs := []*ai.Message{
			ai.NewUserMessage(ai.NewTextPart("Hello")),
			ai.NewModelMessage(ai.NewTextPart("Hi")),
		}

		h := NewHistoryFromMessages(msgs)
		assert.Equal(t, 2, h.Count())
		assert.Equal(t, msgs, h.Messages())
	})

	t.Run("multiple additions", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()

		h.Add("First", "First response")
		h.Add("Second", "Second response")
		h.Add("Third", "Third response")

		assert.Equal(t, 6, h.Count()) // 3 pairs
		msgs := h.Messages()
		assert.Equal(t, ai.RoleUser, msgs[0].Role)
		assert.Equal(t, ai.RoleModel, msgs[1].Role)
		assert.Equal(t, ai.RoleUser, msgs[2].Role)
		assert.Equal(t, ai.RoleModel, msgs[3].Role)
	})
}
