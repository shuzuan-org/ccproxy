package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/binn/ccproxy/internal/admin"
	"github.com/binn/ccproxy/internal/auth"
	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/disguise"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
	"github.com/binn/ccproxy/internal/observe"
	"github.com/binn/ccproxy/internal/proxy"
	"github.com/binn/ccproxy/internal/ratelimit"
	"github.com/binn/ccproxy/internal/updater"
)

// Server holds the HTTP server and its dependencies.
type Server struct {
	cfg        *config.Config
	httpServer *http.Server
	oauthMgr   *oauth.Manager
	balancer   *loadbalancer.Balancer
	updater    *updater.Updater
	cancel     context.CancelFunc
}

// New constructs a fully wired Server from the given config.
func New(cfg *config.Config, version string) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 1. Create account registry from persistent storage.
	registry := config.NewAccountRegistry("data")
	runtimeAccounts := cfg.RuntimeAccounts(registry)

	// 2. Create concurrency tracker and load balancer.
	tracker := loadbalancer.NewConcurrencyTracker()
	balancer := loadbalancer.NewBalancer(runtimeAccounts, tracker)
	balancer.LoadState("data")
	balancer.StartCleanup(ctx)
	balancer.StartPersistence(ctx, "data")

	// 3. Create disguise engine.
	disguiseEngine := disguise.NewEngine("data")
	disguiseEngine.StartSessionCleanup(ctx)

	// 4. Create OAuth manager (all accounts use OAuth).
	store, err := oauth.NewTokenStore("data")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create oauth token store: %w", err)
	}
	oauthMgr := oauth.NewManager(registry.Names(), store, registry.GetProxy)

	// 5. Create PKCE session store for browser-based OAuth login.
	oauthSessions := oauth.NewSessionStore()
	oauthSessions.StartCleanup(ctx, time.Minute)

	// Log account configuration summary.
	for _, acct := range runtimeAccounts {
		proxyInfo := ""
		if acct.Proxy != "" {
			proxyInfo = "(via proxy)"
		}
		slog.Info("account configured",
			"name", acct.Name,
			"enabled", acct.IsEnabled(),
			"max_concurrency", acct.MaxConcurrency,
			"proxy", proxyInfo,
		)
	}

	// Log OAuth token status on startup.
	for _, acct := range runtimeAccounts {
		token, err := store.Load(acct.Name)
		if err != nil {
			slog.Warn("startup: token load error", "account", acct.Name, "error", err.Error())
		} else if token == nil {
			slog.Warn("startup: no token stored, login required", "account", acct.Name)
		} else if time.Until(token.ExpiresAt) < 0 {
			slog.Warn("startup: token expired", "account", acct.Name, "expired_ago", time.Since(token.ExpiresAt).String())
		} else {
			slog.Info("startup: token valid", "account", acct.Name, "expires_in", time.Until(token.ExpiresAt).String())
		}
	}

	// Start auto-refresh for OAuth tokens.
	oauthMgr.StartAutoRefresh(ctx)
	slog.Info("oauth auto-refresh started")

	// 5b. Create usage fetcher for adaptive backpressure.
	usageFetcher := loadbalancer.NewUsageFetcher(
		&oauthTokenAdapter{mgr: oauthMgr},
		"claude-cli/2.1.25 (external, cli)",
	)
	balancer.SetUsageFetcher(usageFetcher)
	usageFetcher.StartBackground(ctx,
		func() []string { return registry.Names() },
		func(name string) *loadbalancer.BudgetController {
			h := balancer.GetHealth(name)
			if h != nil {
				return h.Budget()
			}
			return nil
		},
	)
	slog.Info("usage fetcher started")

	// Create auto-updater.
	checkInterval, _ := time.ParseDuration(cfg.Server.UpdateCheckInterval)
	if checkInterval == 0 {
		checkInterval = time.Hour
	}
	upd := updater.New(updater.Config{
		CurrentVersion: version,
		Repo:           cfg.Server.UpdateRepo,
		CheckInterval:  checkInterval,
		AutoUpdate:     cfg.Server.IsAutoUpdateEnabled(),
		APIURL:         cfg.Server.UpdateAPIURL,
	})
	go upd.Start(ctx)

	// Start periodic metrics logging with update status.
	updateProv := observe.UpdateStatusProvider(&updateAdapter{upd: upd})
	observe.Global.StartPeriodicLog(ctx, 5*time.Minute, balancer, updateProv, nil)

	// 6. Register onChange callback to propagate dynamic account changes.
	registry.SetOnChange(func(accounts []config.Account) {
		runtime := cfg.RuntimeAccounts(registry)
		balancer.UpdateAccounts(runtime)
		oauthMgr.UpdateAccounts(registry.Names())
		slog.Info("accounts updated dynamically", "count", len(accounts))
	})

	// 7. Create proxy handler.
	proxyHandler := proxy.NewHandler(cfg.Server.BaseURL, cfg.Server.RequestTimeout, balancer, disguiseEngine, oauthMgr)

	// 8. Create admin handler.
	adminHandler := admin.NewHandler(balancer, oauthMgr, oauthSessions, cfg, registry, upd)

	// 9. Setup HTTP mux with route groups.
	mux := http.NewServeMux()

	// API routes — require bearer token auth.
	mux.Handle("/v1/messages", auth.Middleware(cfg.APIKeys)(http.HandlerFunc(proxyHandler.ServeHTTP)))
	mux.Handle("/v1/messages/count_tokens", auth.Middleware(cfg.APIKeys)(http.HandlerFunc(proxyHandler.ServeHTTP)))

	// Admin routes — rate-limited and protected by basic auth.
	limiter := ratelimit.NewLimiter(cfg.Server.RateLimit, time.Minute)
	limiter.StartCleanup(ctx)
	adminRL := ratelimit.Middleware(limiter)
	adminAuth := basicAuth(cfg.Server.AdminPassword)

	mux.Handle("/api/accounts", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleAccounts))))
	mux.Handle("/api/accounts/add", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleAddAccount))))
	mux.Handle("/api/accounts/remove", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleRemoveAccount))))
	mux.Handle("/api/accounts/proxy", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleUpdateProxy))))
	mux.Handle("/api/sessions", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleSessions))))
	mux.Handle("/api/oauth/login/start", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleOAuthLoginStart))))
	mux.Handle("/api/oauth/login/complete", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleOAuthLoginComplete))))
	mux.Handle("/api/oauth/refresh", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleOAuthRefresh))))
	mux.Handle("/api/oauth/logout", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleOAuthLogout))))
	mux.Handle("/api/update/status", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleUpdateStatus))))
	mux.Handle("/api/update/check", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleUpdateCheck))))
	mux.Handle("/api/update/apply", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleUpdateApply))))
	mux.Handle("/admin/", adminRL(adminAuth(http.StripPrefix("/admin", adminHandler.HandleDashboard()))))

	// Health check — no auth required.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Wrap the mux with recovery and request logging middleware.
	handler := recoveryMiddleware(requestLogMiddleware(mux))

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 0, // disabled: SSE streams need unbounded write time; per-request deadlines are set in the proxy handler
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		cfg:        cfg,
		httpServer: httpServer,
		oauthMgr:   oauthMgr,
		balancer:   balancer,
		updater:    upd,
		cancel:     cancel,
	}, nil
}

// Start begins listening and serving HTTP requests.
// It returns nil when the server is shut down gracefully.
func (s *Server) Start() error {
	slog.Info("ccproxy starting", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the HTTP server and persists health state.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down server")
	s.cancel() // cancel background goroutines
	if s.balancer != nil {
		if err := s.balancer.SaveState("data"); err != nil {
			slog.Error("failed to save health state on shutdown", "error", err.Error())
		} else {
			slog.Info("health state saved on shutdown")
		}
	}
	err := s.httpServer.Shutdown(ctx)
	if err != nil {
		slog.Error("http server shutdown error", "error", err.Error())
	} else {
		slog.Info("http server stopped gracefully")
	}
	return err
}

// basicAuth returns a middleware that enforces HTTP Basic Auth using the given password.
// The username field is ignored; only the password is checked.
func basicAuth(password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pass, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="ccproxy admin"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requestLogMiddleware logs each incoming request method, path, and duration.
func requestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		elapsed := time.Since(start)
		lvl := slog.LevelInfo
		if lrw.statusCode >= 500 {
			lvl = slog.LevelError
		} else if lrw.statusCode >= 400 {
			lvl = slog.LevelWarn
		}
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", lrw.statusCode,
			"elapsed", elapsed.String(),
			"remote", r.RemoteAddr,
		}
		if rc := observe.GetRequestContext(r.Context()); rc != nil {
			attrs = append(attrs, "request_id", rc.RequestID)
		}
		slog.Log(r.Context(), lvl, "http request", attrs...)
	})
}

// recoveryMiddleware catches panics and returns HTTP 500.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "panic", rec)
					// http.Error is safe to call even if headers were already sent —
				// net/http silently ignores the superfluous WriteHeader call.
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// loggingResponseWriter captures the status code written by a handler.
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying ResponseWriter if it supports http.Flusher.
// This is critical for SSE streaming — without it, events are buffered and
// delivered in bulk instead of being flushed to the client in real time.
func (lrw *loggingResponseWriter) Flush() {
	if f, ok := lrw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// oauthTokenAdapter adapts oauth.Manager to the OAuthTokenProvider interface
// used by the usage fetcher.
type oauthTokenAdapter struct {
	mgr *oauth.Manager
}

func (a *oauthTokenAdapter) GetValidToken(ctx context.Context, accountName string) (string, error) {
	token, err := a.mgr.GetValidToken(ctx, accountName)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// updateAdapter adapts *updater.Updater to observe.UpdateStatusProvider.
type updateAdapter struct {
	upd *updater.Updater
}

func (a *updateAdapter) Status() observe.UpdateStatus {
	if a.upd == nil {
		return observe.UpdateStatus{}
	}
	s := a.upd.Status()
	return observe.UpdateStatus{
		CurrentVersion: s.CurrentVersion,
		LatestVersion:  s.LatestVersion,
		LastCheck:      s.LastCheck,
	}
}
