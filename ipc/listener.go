package ipc

import (
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
)

const (
	bufferSize = 4096
	socketMode = 0o660
)

func ListenUnixSocket(socketPath string, handler func(msg IPCMessage) error) {
	removeExistingSocket(socketPath)

	socket, err := createUnixListener(socketPath)
	if err != nil {
		log.Error().Err(err).Msg("failed to create unix socket")

		_ = os.Remove(socketPath)

		os.Exit(1)
	}
	defer socket.Close()

	signals := make(chan os.Signal, 1)

	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	go shutdownOnSignal(socket, socketPath, signals)

	for {
		conn, err := socket.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			log.Error().Err(err).Msg("failed to accept connection")

			return
		}

		go handleIncomingConnection(conn, handler)
	}
}

func removeExistingSocket(socketPath string) {
	removeErr := os.Remove(socketPath)
	if removeErr != nil && !os.IsNotExist(removeErr) {
		log.Fatal().
			Err(removeErr).
			Msg("failed to remove existing socket file")
	}
}

func createUnixListener(socketPath string) (*net.UnixListener, error) {
	socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}

	chmodErr := os.Chmod(socketPath, socketMode)
	if chmodErr != nil {
		_ = socket.Close()
		return nil, chmodErr
	}

	return socket, nil
}

func shutdownOnSignal(socket *net.UnixListener, socketPath string, signals <-chan os.Signal) {
	<-signals
	log.Info().Msg("received termination signal, shutting down")

	closeErr := socket.Close()
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		log.Error().Err(closeErr).Msg("failed to close unix socket")
	}

	removeErr := os.Remove(socketPath)
	if removeErr != nil && !os.IsNotExist(removeErr) {
		log.Error().Err(removeErr).Msg("failed to remove unix socket")
	}
}

func handleIncomingConnection(conn *net.UnixConn, handler func(msg IPCMessage) error) {
	defer conn.Close()

	buf := make([]byte, bufferSize)

	bytesRead, err := conn.Read(buf)
	if err != nil {
		log.Error().Err(err).Msg("failed to read from connection")
		return
	}

	parsedMessage, parseErr := ParseMessage(buf[:bytesRead])
	if parseErr != nil {
		log.Error().Err(parseErr).Msg("failed to parse message")
		return
	}

	handlerErr := handler(parsedMessage)
	if handlerErr != nil {
		log.Error().Err(handlerErr).Msg("handler returned an error")
	}
}
