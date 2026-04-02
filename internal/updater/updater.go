package updater

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creativeprojects/go-selfupdate"
)

// Config holds updater configuration.
type Config struct {
	CurrentVersion string
	Repo           string        // "owner/repo"
	CheckInterval  time.Duration
	AutoUpdate     bool
	APIURL         string // GitHub Enterprise API base URL (empty = github.com)
	Channel        string // "stable" | "beta"; empty defaults to stable behaviour
}

// UpdateStatus represents the current update state.
type UpdateStatus struct {
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	LastCheck      time.Time `json:"last_check"`
	AutoUpdate     bool      `json:"auto_update"`
	Channel        string    `json:"channel"`
	Checking       bool      `json:"checking"`
	Updating       bool      `json:"updating"`
}

// Updater checks for and applies updates from GitHub Releases.
type Updater struct {
	cfg      Config
	isDev    bool
	isDocker bool

	mu        sync.RWMutex
	latest    string
	lastCheck time.Time
	checking  bool
	updating  bool

	applyMu sync.Mutex // serializes Apply calls
}

// New creates an Updater. Does not start background checking.
func New(cfg Config) *Updater {
	_, dockerErr := os.Stat("/.dockerenv")

	return &Updater{
		cfg:      cfg,
		isDev:    cfg.CurrentVersion == "dev",
		isDocker: dockerErr == nil,
	}
}

// IsDocker returns true if running inside a Docker container.
func (u *Updater) IsDocker() bool {
	return u.isDocker
}

// Status returns the current update status.
func (u *Updater) Status() UpdateStatus {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return UpdateStatus{
		CurrentVersion: u.cfg.CurrentVersion,
		LatestVersion:  u.latest,
		LastCheck:      u.lastCheck,
		AutoUpdate:     u.cfg.AutoUpdate,
		Channel:        u.cfg.Channel,
		Checking:       u.checking,
		Updating:       u.updating,
	}
}

// Start launches the background update check loop. Blocks until ctx is cancelled.
// Returns immediately if auto-update is disabled, version is "dev", or running in Docker.
func (u *Updater) Start(ctx context.Context) {
	if !u.cfg.AutoUpdate || u.isDev || u.isDocker {
		if u.isDev {
			slog.Info("auto-update disabled: dev version")
		} else if u.isDocker {
			slog.Info("auto-update disabled: running in Docker")
		} else {
			slog.Info("auto-update disabled by config")
		}
		return
	}

	slog.Info("auto-update enabled",
		"schedule", "every hour on the hour",
		"repo", u.cfg.Repo,
	)

	// Initial check after a short delay, respecting context.
	initialTimer := time.NewTimer(30 * time.Second)
	defer initialTimer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-initialTimer.C:
		u.checkAndApply(ctx)
	}

	// Check at the top of every hour.
	for {
		now := time.Now()
		next := now.Truncate(time.Hour).Add(time.Hour)
		delay := next.Sub(now)

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			u.checkAndApply(ctx)
		}
	}
}

// CheckNow performs an immediate version check. Returns the latest version found.
func (u *Updater) CheckNow(ctx context.Context) (string, error) {
	release, _, err := u.findLatest(ctx)
	if err != nil {
		return "", err
	}
	if release == nil {
		return u.cfg.CurrentVersion, nil
	}
	return release.Version(), nil
}

// Apply checks for update and applies it if available. Returns (updated, newVersion, error).
// Serialized via applyMu to prevent concurrent binary replacement.
func (u *Updater) Apply(ctx context.Context, force bool) (bool, string, error) {
	u.applyMu.Lock()
	defer u.applyMu.Unlock()

	u.mu.Lock()
	u.updating = true
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.updating = false
		u.mu.Unlock()
	}()

	release, updater, err := u.findLatest(ctx)
	if err != nil {
		return false, "", err
	}
	if release == nil {
		return false, u.cfg.CurrentVersion, nil
	}

	if release.LessOrEqual(u.cfg.CurrentVersion) {
		if !force {
			return false, release.Version(), nil
		}
		// force=true: allow re-install of same version, but not downgrade.
		if release.LessThan(u.cfg.CurrentVersion) {
			return false, release.Version(), nil
		}
	}

	exe, err := selfupdate.ExecutablePath()
	if err != nil {
		return false, "", fmt.Errorf("find executable path: %w", err)
	}

	if err := updater.UpdateTo(ctx, release, exe); err != nil {
		return false, "", fmt.Errorf("apply update: %w", err)
	}

	slog.Info("update applied",
		"from", u.cfg.CurrentVersion,
		"to", release.Version(),
	)
	return true, release.Version(), nil
}

// Restart sends SIGTERM to the current process to trigger graceful shutdown.
// Note: the existing signal handler in cli/root.go handles SIGTERM and
// calls srv.Shutdown with a 10-second drain timeout for in-flight requests.
func (u *Updater) Restart() {
	slog.Info("restarting process for update")
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		slog.Error("failed to find own process", "error", err)
		return
	}
	_ = p.Signal(syscall.SIGTERM)
}

func (u *Updater) checkAndApply(ctx context.Context) {
	updated, newVersion, err := u.Apply(ctx, false)
	if err != nil {
		slog.Warn("auto-update check failed", "error", err)
		return
	}
	if updated {
		slog.Info("auto-update: upgrade successful, restarting",
			"from", u.cfg.CurrentVersion,
			"to", newVersion,
		)
		u.Restart()
		// Block until context is cancelled to prevent ticker from triggering
		// another Apply during SIGTERM graceful shutdown.
		<-ctx.Done()
	}
}

// findLatest detects the latest release from GitHub. Returns (release, updater, error).
// The updater instance is returned so Apply can call UpdateTo on it.
func (u *Updater) findLatest(ctx context.Context) (*selfupdate.Release, *selfupdate.Updater, error) {
	u.mu.Lock()
	u.checking = true
	u.mu.Unlock()

	var succeeded bool
	defer func() {
		u.mu.Lock()
		u.checking = false
		if succeeded {
			u.lastCheck = time.Now()
		}
		u.mu.Unlock()
	}()

	source, err := selfupdate.NewGitHubSource(selfupdate.GitHubConfig{
		EnterpriseBaseURL: u.cfg.APIURL,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create github source: %w", err)
	}

	upd, err := selfupdate.NewUpdater(selfupdate.Config{
		Source:     source,
		Validator:  &selfupdate.ChecksumValidator{UniqueFilename: "checksums.txt"},
		Prerelease: u.cfg.Channel == "beta",
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create updater: %w", err)
	}

	parts := strings.SplitN(u.cfg.Repo, "/", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid repo format %q, expected owner/repo", u.cfg.Repo)
	}
	slug := selfupdate.NewRepositorySlug(parts[0], parts[1])

	release, found, err := upd.DetectLatest(ctx, slug)
	if err != nil {
		return nil, nil, fmt.Errorf("detect latest: %w", err)
	}
	if !found {
		succeeded = true
		return nil, nil, nil
	}

	u.mu.Lock()
	u.latest = release.Version()
	u.mu.Unlock()

	succeeded = true
	return release, upd, nil
}
