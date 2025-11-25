package agent

import (
	"sync"
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
		// Messages() returns a copy, so we compare by length and content
		result := h.Messages()
		require.Len(t, result, 2)
		assert.Equal(t, ai.RoleUser, result[0].Role)
		assert.Equal(t, ai.RoleModel, result[1].Role)
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

	t.Run("add nil message is ignored", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()

		h.AddMessage(nil)
		assert.Equal(t, 0, h.Count(), "nil message should be ignored")
	})

	t.Run("messages returns copy", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()
		h.Add("Hello", "Hi")

		msgs1 := h.Messages()
		msgs2 := h.Messages()

		// Should be different slices
		msgs1[0] = nil
		assert.NotNil(t, msgs2[0], "modifying returned slice should not affect other calls")
		assert.Equal(t, 2, h.Count(), "internal state should be unchanged")
	})
}

// TestHistory_ConcurrentAccess tests thread-safety of History operations
func TestHistory_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("concurrent writes are safe", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				h.Add("user msg", "response")
			}(i)
		}
		wg.Wait()

		assert.Equal(t, 200, h.Count()) // 100 pairs
	})

	t.Run("concurrent reads are safe", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()
		h.Add("Hello", "Hi")
		h.Add("Test", "Response")

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = h.Messages()
				_ = h.Count()
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent read-write is safe", func(t *testing.T) {
		t.Parallel()
		h := NewHistory()

		var wg sync.WaitGroup
		// Writers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.Add("msg", "resp")
			}()
		}
		// Readers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = h.Messages()
				_ = h.Count()
			}()
		}
		wg.Wait()
	})
}
