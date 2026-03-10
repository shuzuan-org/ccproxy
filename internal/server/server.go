package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/binn/ccproxy/internal/admin"
	"github.com/binn/ccproxy/internal/auth"
	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/disguise"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
	"github.com/binn/ccproxy/internal/proxy"
)

// Server holds the HTTP server and its dependencies.
type Server struct {
	cfg        *config.Config
	httpServer *http.Server
	oauthMgr   *oauth.Manager
}

// New constructs a fully wired Server from the given config.
func New(cfg *config.Config) (*Server, error) {
	// 1. Create concurrency tracker and load balancer.
	tracker := loadbalancer.NewConcurrencyTracker()
	balancer := loadbalancer.NewBalancer(cfg.Instances, tracker)

	// 2. Create disguise engine.
	disguiseEngine := disguise.NewEngine()

	// 3. Create OAuth manager only when at least one instance uses oauth auth_mode.
	var oauthMgr *oauth.Manager
	for _, inst := range cfg.Instances {
		if inst.IsOAuth() {
			store, err := oauth.NewTokenStore("data")
			if err != nil {
				return nil, fmt.Errorf("create oauth token store: %w", err)
			}
			oauthMgr = oauth.NewManager(cfg.OAuthProviders, store)
			break
		}
	}

	// 4. Create proxy handler.
	proxyHandler := proxy.NewHandler(cfg.Instances, balancer, disguiseEngine, oauthMgr)

	// 5. Create admin handler.
	adminHandler := admin.NewHandler(balancer)

	// 6. Setup HTTP mux with route groups.
	mux := http.NewServeMux()

	// API route — requires bearer token auth.
	mux.Handle("/v1/messages", auth.Middleware(cfg.APIKeys)(http.HandlerFunc(proxyHandler.ServeHTTP)))

	// Admin routes — optionally protected by basic auth.
	var adminMiddleware func(http.Handler) http.Handler
	if cfg.Server.AdminPassword != "" {
		adminMiddleware = basicAuth(cfg.Server.AdminPassword)
	} else {
		adminMiddleware = noopMiddleware
	}

	mux.Handle("/api/instances", adminMiddleware(http.HandlerFunc(adminHandler.HandleInstances)))
	mux.Handle("/api/sessions", adminMiddleware(http.HandlerFunc(adminHandler.HandleSessions)))
	mux.Handle("/admin/", adminMiddleware(http.StripPrefix("/admin", adminHandler.HandleDashboard())))

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
	}, nil
}

// Start begins listening and serving HTTP requests.
// It returns nil when the server is shut down gracefully.
func (s *Server) Start() error {
	log.Printf("ccproxy starting on %s", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("shutting down server...")
	return s.httpServer.Shutdown(ctx)
}

// basicAuth returns a middleware that enforces HTTP Basic Auth using the given password.
// The username field is ignored; only the password is checked.
func basicAuth(password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pass, ok := r.BasicAuth()
			if !ok || pass != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="ccproxy admin"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// noopMiddleware passes requests through unchanged.
func noopMiddleware(next http.Handler) http.Handler {
	return next
}

// requestLogMiddleware logs each incoming request method, path, and duration.
func requestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, lrw.statusCode, time.Since(start))
	})
}

// recoveryMiddleware catches panics and returns HTTP 500.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %v", rec)
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
