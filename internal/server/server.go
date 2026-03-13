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
	"github.com/binn/ccproxy/internal/proxy"
	"github.com/binn/ccproxy/internal/ratelimit"
)

// Server holds the HTTP server and its dependencies.
type Server struct {
	cfg        *config.Config
	httpServer *http.Server
	oauthMgr   *oauth.Manager
	balancer   *loadbalancer.Balancer
	cancel     context.CancelFunc
}

// New constructs a fully wired Server from the given config.
func New(cfg *config.Config) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 1. Create instance registry from persistent storage.
	registry := config.NewInstanceRegistry("data")
	runtimeInstances := cfg.RuntimeInstances(registry)

	// 2. Create concurrency tracker and load balancer.
	tracker := loadbalancer.NewConcurrencyTracker()
	balancer := loadbalancer.NewBalancer(runtimeInstances, tracker)
	balancer.LoadState("data")
	balancer.StartCleanup(ctx)
	balancer.StartPersistence(ctx, "data")

	// 3. Create disguise engine.
	disguiseEngine := disguise.NewEngine("data")
	disguiseEngine.StartSessionCleanup(ctx)

	// 4. Create OAuth manager (all instances use OAuth).
	store, err := oauth.NewTokenStore("data")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create oauth token store: %w", err)
	}
	oauthMgr := oauth.NewManager(registry.Names(), store, registry.GetProxy)

	// 5. Create PKCE session store for browser-based OAuth login.
	oauthSessions := oauth.NewSessionStore()
	oauthSessions.StartCleanup(ctx, time.Minute)

	// Log instance configuration summary.
	for _, inst := range runtimeInstances {
		proxyInfo := ""
		if inst.Proxy != "" {
			proxyInfo = "(via proxy)"
		}
		slog.Info("instance configured",
			"name", inst.Name,
			"enabled", inst.IsEnabled(),
			"max_concurrency", inst.MaxConcurrency,
			"proxy", proxyInfo,
		)
	}

	// Log OAuth token status on startup.
	for _, inst := range runtimeInstances {
		token, err := store.Load(inst.Name)
		if err != nil {
			slog.Warn("startup: token load error", "instance", inst.Name, "error", err.Error())
		} else if token == nil {
			slog.Warn("startup: no token stored, login required", "instance", inst.Name)
		} else if time.Until(token.ExpiresAt) < 0 {
			slog.Warn("startup: token expired", "instance", inst.Name, "expired_ago", time.Since(token.ExpiresAt).String())
		} else {
			slog.Info("startup: token valid", "instance", inst.Name, "expires_in", time.Until(token.ExpiresAt).String())
		}
	}

	// Start auto-refresh for OAuth tokens.
	oauthMgr.StartAutoRefresh(ctx)
	slog.Info("oauth auto-refresh started")

	// 6. Register onChange callback to propagate dynamic instance changes.
	registry.SetOnChange(func(instances []config.Instance) {
		runtime := cfg.RuntimeInstances(registry)
		balancer.UpdateInstances(runtime)
		oauthMgr.UpdateInstances(registry.Names())
		slog.Info("instances updated dynamically", "count", len(instances))
	})

	// 7. Create proxy handler.
	proxyHandler := proxy.NewHandler(cfg.Server.BaseURL, cfg.Server.RequestTimeout, balancer, disguiseEngine, oauthMgr)

	// 8. Create admin handler.
	adminHandler := admin.NewHandler(balancer, oauthMgr, oauthSessions, cfg, registry)

	// 9. Setup HTTP mux with route groups.
	mux := http.NewServeMux()

	// API route — requires bearer token auth.
	mux.Handle("/v1/messages", auth.Middleware(cfg.APIKeys)(http.HandlerFunc(proxyHandler.ServeHTTP)))

	// Admin routes — rate-limited and protected by basic auth.
	limiter := ratelimit.NewLimiter(cfg.Server.RateLimit, time.Minute)
	limiter.StartCleanup(ctx)
	adminRL := ratelimit.Middleware(limiter)
	adminAuth := basicAuth(cfg.Server.AdminPassword)

	mux.Handle("/api/instances", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleInstances))))
	mux.Handle("/api/instances/add", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleAddInstance))))
	mux.Handle("/api/instances/remove", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleRemoveInstance))))
	mux.Handle("/api/instances/proxy", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleUpdateProxy))))
	mux.Handle("/api/sessions", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleSessions))))
	mux.Handle("/api/oauth/login/start", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleOAuthLoginStart))))
	mux.Handle("/api/oauth/login/complete", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleOAuthLoginComplete))))
	mux.Handle("/api/oauth/refresh", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleOAuthRefresh))))
	mux.Handle("/api/oauth/logout", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleOAuthLogout))))
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
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		cfg:        cfg,
		httpServer: httpServer,
		oauthMgr:   oauthMgr,
		balancer:   balancer,
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
		slog.Log(r.Context(), lvl, "http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", lrw.statusCode,
			"elapsed", elapsed.String(),
			"remote", r.RemoteAddr,
		)
	})
}

// recoveryMiddleware catches panics and returns HTTP 500.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "panic", rec)
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
