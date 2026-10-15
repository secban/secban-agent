package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/secban/secban-agent/ban/banloader"
	"gitlab.com/secban/secban-agent/config"
	"gitlab.com/secban/secban-agent/db"
	"gitlab.com/secban/secban-agent/dispatcher"
	"gitlab.com/secban/secban-agent/ip"
	"gitlab.com/secban/secban-agent/router"
)

const (
	shutdownTimeout = 5 * time.Second
	socketMode      = 0o660
	maxHeaderBytes  = 8192
)

func main() {
	conf := loadConf()

	zerolog.SetGlobalLevel(conf.LogLevel)

	ipInit(conf)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dispatcherInit(ctx, conf)

	dbInit(ctx, conf)

	var waitGroup sync.WaitGroup

	if conf.ListenTCP != "" {
		waitGroup.Go(func() {
			listenTcp(ctx, conf.ListenTCP)
		})
	}

	if conf.ListenUnix != "" {
		waitGroup.Go(func() {
			listenUnix(ctx, conf.ListenUnix)
		})
	}

	waitGroup.Wait()

	exitErr := dispatcher.Exit(ctx)
	if exitErr != nil {
		log.Error().Err(exitErr).Msg("dispatcher exit error")
	}
}

func loadConf() *config.Config {
	var configDir string

	flag.StringVar(&configDir, "config", "/etc/secban", "path to config directory")
	flag.Parse()

	conf, confErr := config.LoadConfig(configDir)
	if confErr != nil {
		log.Fatal().Err(confErr).Msg("failed to load config")
	}

	return conf
}

func ipInit(conf *config.Config) {
	ipErr := ip.Init(conf.AllowList, conf.AllowLocal, conf.AllowLoopback)
	if ipErr != nil {
		log.Fatal().Err(ipErr).Msg("ip allowlist init failed")
	}
}

func dbInit(ctx context.Context, conf *config.Config) {
	if conf.Database == "" {
		return
	}

	dbErr := db.Init(ctx, conf.Database)
	if dbErr != nil {
		log.Fatal().Err(dbErr).Msg("database init failed")
	}
}

func dispatcherInit(ctx context.Context, conf *config.Config) {
	actor, loadErr := banloader.Load(conf.BanMethod)
	if loadErr != nil {
		log.Fatal().Err(loadErr).Msg("failed to load ban method")
	}

	banLogEnabled := conf.Database != ""

	dispatcherErr := dispatcher.Init(ctx, conf.Rules, actor, banLogEnabled)
	if dispatcherErr != nil {
		log.Fatal().Err(dispatcherErr).Msg("dispatcher init failed")
	}
}

func listenTcp(ctx context.Context, addr string) {
	server := &http.Server{
		Addr:              addr,
		Handler:           router.NewRouter(),
		ReadTimeout:       1 * time.Second,
		ReadHeaderTimeout: 1 * time.Second,
		WriteTimeout:      1 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	serverErrChan := make(chan error, 1)

	go func() {
		log.Info().Str("addr", addr).Msg("TCP server starting")

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

	log.Info().Msg("TCP server shutting down")

	shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()

	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		log.Error().Err(shutdownErr).Msg("server shutdown error")
	}
}

func listenUnix(ctx context.Context, addr string) {
	server := &http.Server{
		Handler:           router.NewRouter(),
		ReadTimeout:       1 * time.Second,
		ReadHeaderTimeout: 1 * time.Second,
		WriteTimeout:      1 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	removeErr := os.Remove(addr)
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		log.Fatal().Err(removeErr).Msg("failed to remove unix socket")
	}

	listenConfig := net.ListenConfig{}

	unixListener, listenErr := listenConfig.Listen(ctx, "unix", addr)
	if listenErr != nil {
		log.Fatal().Err(listenErr).Msg("failed to create unix listener")
	}

	chmodErr := os.Chmod(addr, socketMode)
	if chmodErr != nil {
		log.Fatal().Err(chmodErr).Msg("failed to set unix socket permissions")
	}

	serverErrChan := make(chan error, 1)

	go func() {
		log.Info().Str("addr", addr).Msg("Unix server starting")

		serveErr := server.Serve(unixListener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrChan <- serveErr
		}
	}()

	select {
	case <-ctx.Done():
	case serveErr := <-serverErrChan:
		log.Fatal().Err(serveErr).Msg("server listen error")
	}

	log.Info().Msg("Unix server shutting down")

	shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()

	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		log.Error().Err(shutdownErr).Msg("server shutdown error")
	}
}
