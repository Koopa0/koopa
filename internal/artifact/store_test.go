//go:build integration

package artifact_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koopa0/koopa-cli/internal/artifact"
	"github.com/koopa0/koopa-cli/internal/testutil"
)

func TestStore_Save_And_Get(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.SetupTestDB(t)
	store := artifact.New(db.Queries, nil)
	sessionID := uuid.New()

	// Create artifact
	art := &artifact.Artifact{
		SessionID: sessionID,
		Filename:  "main.go",
		Type:      artifact.TypeCode,
		Language:  "go",
		Title:     "Main Entry Point",
		Content:   "package main\n\nfunc main() {}",
	}

	err := store.Save(ctx, art)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, art.ID)
	assert.Equal(t, 1, art.Version)

	// Get artifact
	got, err := store.Get(ctx, sessionID, "main.go")
	require.NoError(t, err)
	assert.Equal(t, art.ID, got.ID)
	assert.Equal(t, "main.go", got.Filename)
	assert.Equal(t, artifact.TypeCode, got.Type)
	assert.Equal(t, "go", got.Language)
	assert.Equal(t, "package main\n\nfunc main() {}", got.Content)
}

func TestStore_Save_Update_IncrementsVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.SetupTestDB(t)
	store := artifact.New(db.Queries, nil)
	sessionID := uuid.New()

	// Create artifact
	art := &artifact.Artifact{
		SessionID: sessionID,
		Filename:  "readme.md",
		Type:      artifact.TypeMarkdown,
		Content:   "# Hello",
	}

	err := store.Save(ctx, art)
	require.NoError(t, err)
	assert.Equal(t, 1, art.Version)

	// Update same artifact
	art.Content = "# Hello World"
	err = store.Save(ctx, art)
	require.NoError(t, err)
	assert.Equal(t, 2, art.Version)

	// Verify updated content
	got, err := store.Get(ctx, sessionID, "readme.md")
	require.NoError(t, err)
	assert.Equal(t, "# Hello World", got.Content)
	assert.Equal(t, 2, got.Version)
}

func TestStore_Get_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.SetupTestDB(t)
	store := artifact.New(db.Queries, nil)

	_, err := store.Get(ctx, uuid.New(), "nonexistent.txt")
	assert.ErrorIs(t, err, artifact.ErrNotFound)
}

func TestStore_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.SetupTestDB(t)
	store := artifact.New(db.Queries, nil)
	sessionID := uuid.New()

	// Create multiple artifacts
	files := []string{"main.go", "helper.go", "README.md"}
	for _, f := range files {
		art := &artifact.Artifact{
			SessionID: sessionID,
			Filename:  f,
			Type:      artifact.TypeCode,
			Content:   "content",
		}
		require.NoError(t, store.Save(ctx, art))
	}

	// List artifacts
	list, err := store.List(ctx, sessionID)
	require.NoError(t, err)
	assert.Len(t, list, 3)

	// Verify all filenames present
	listMap := make(map[string]bool)
	for _, f := range list {
		listMap[f] = true
	}
	for _, f := range files {
		assert.True(t, listMap[f], "expected %s in list", f)
	}
}

func TestStore_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.SetupTestDB(t)
	store := artifact.New(db.Queries, nil)
	sessionID := uuid.New()

	// Create artifact
	art := &artifact.Artifact{
		SessionID: sessionID,
		Filename:  "to_delete.txt",
		Type:      artifact.TypeMarkdown,
		Content:   "delete me",
	}
	require.NoError(t, store.Save(ctx, art))

	// Delete artifact
	err := store.Delete(ctx, sessionID, "to_delete.txt")
	require.NoError(t, err)

	// Verify deleted
	_, err = store.Get(ctx, sessionID, "to_delete.txt")
	assert.ErrorIs(t, err, artifact.ErrNotFound)
}

func TestStore_Delete_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.SetupTestDB(t)
	store := artifact.New(db.Queries, nil)

	err := store.Delete(ctx, uuid.New(), "nonexistent.txt")
	assert.ErrorIs(t, err, artifact.ErrNotFound)
}

func TestStore_DeleteBySession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.SetupTestDB(t)
	store := artifact.New(db.Queries, nil)
	sessionID := uuid.New()

	// Create multiple artifacts
	for _, f := range []string{"a.go", "b.go", "c.go"} {
		art := &artifact.Artifact{
			SessionID: sessionID,
			Filename:  f,
			Type:      artifact.TypeCode,
			Content:   "content",
		}
		require.NoError(t, store.Save(ctx, art))
	}

	// Verify artifacts exist
	list, err := store.List(ctx, sessionID)
	require.NoError(t, err)
	assert.Len(t, list, 3)

	// Delete all by session
	err = store.DeleteBySession(ctx, sessionID)
	require.NoError(t, err)

	// Verify all deleted
	list, err = store.List(ctx, sessionID)
	require.NoError(t, err)
	assert.Len(t, list, 0)
}
