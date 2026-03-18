package updater

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})
	assert.NotNil(t, u)

	status := u.Status()
	assert.Equal(t, "1.0.0", status.CurrentVersion)
	assert.Equal(t, "", status.LatestVersion)
	assert.True(t, status.LastCheck.IsZero())
	assert.True(t, status.AutoUpdate)
}

func TestNew_DevVersion(t *testing.T) {
	t.Parallel()
	u := New(Config{
		CurrentVersion: "dev",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})
	assert.NotNil(t, u)
	status := u.Status()
	assert.Equal(t, "dev", status.CurrentVersion)
}

func TestUpdater_StatusFields(t *testing.T) {
	t.Parallel()
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     false,
	})

	status := u.Status()
	assert.False(t, status.AutoUpdate)
	assert.False(t, status.Checking)
	assert.False(t, status.Updating)
}

func TestStart_DevVersion_ReturnsImmediately(t *testing.T) {
	t.Parallel()
	u := New(Config{
		CurrentVersion: "dev",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		u.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-time.After(time.Second):
		t.Fatal("Start did not return for dev version")
	}
}

func TestStart_DisabledByConfig_ReturnsImmediately(t *testing.T) {
	t.Parallel()
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     false,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		u.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-time.After(time.Second):
		t.Fatal("Start did not return when disabled")
	}
}

func TestStart_RespectsContextCancellation(t *testing.T) {
	t.Parallel()
	if New(Config{}).isDocker {
		t.Skip("running in Docker, ticker loop exits early")
	}

	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		u.Start(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not respect context cancellation")
	}
}

func TestIsDocker(t *testing.T) {
	t.Parallel()
	u := New(Config{CurrentVersion: "1.0.0"})
	// Just verify it returns a bool without panicking.
	_ = u.IsDocker()
}
