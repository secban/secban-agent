package profiler

import (
	"context"
	"errors"
	"net/http"
	"time"

	_ "net/http/pprof" //nolint:gosec // Profiling endpoint enabled intentionally when requested.

	"github.com/rs/zerolog/log"
)

const (
	shutdownTimeout = 1 * time.Second
	tcpReadTimeout  = 1 * time.Second
	tcpWriteTimeout = 1 * time.Second
	tcpIdleTimeout  = 1 * time.Second
)

func Listen(ctx context.Context, addr string) {
	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  tcpReadTimeout,
		WriteTimeout: tcpWriteTimeout,
		IdleTimeout:  tcpIdleTimeout,
	}

	serverErrChan := make(chan error, 1)

	go func() {
		log.Info().Str("addr", addr).Msg("PPROF server starting")

		serveErr := server.ListenAndServe()
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrChan <- serveErr
		}
	}()

	select {
	case <-ctx.Done():
	case serveErr := <-serverErrChan:
		log.Fatal().Err(serveErr).Msg("server listen error")
	}

	log.Info().Msg("PPROF server shutting down")

	shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()

	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		log.Error().Err(shutdownErr).Msg("server shutdown error")
	}
}
