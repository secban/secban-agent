package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"gitlab.com/thequietbot/secban/secban-agent/offender"
)

const timeout = 1 * time.Second

type IPCArgs struct {
	IP       string
	Rule     string
	Offender offender.Offender
	Sockets  []string
}

type IPCMessage struct {
	IP       string            `json:"ip"`
	Rule     string            `json:"rule"`
	Offender offender.Offender `json:"offender"`
}

func Message(ctx context.Context, args IPCArgs) {
	log.Debug().
		Str("ip", args.IP).
		Str("rule", args.Rule).
		Str("sockets", fmt.Sprintf("%v", args.Sockets)).
		Msg("sending IPC message")

	if len(args.Sockets) == 0 {
		log.Warn().
			Str("ip", args.IP).
			Str("rule", args.Rule).
			Msg("no ipc channels specified")

		return
	}

	msg := IPCMessage{
		IP:       args.IP,
		Rule:     args.Rule,
		Offender: args.Offender,
	}

	messageJSON, marshallErr := json.Marshal(msg)
	if marshallErr != nil {
		log.Error().
			Str("ip", args.IP).
			Str("rule", args.Rule).
			Err(marshallErr).
			Msg("failed to marshal IPC message to JSON")

		return
	}

	for _, socket := range args.Sockets {
		go message(ctx, socket, messageJSON)
	}
}

func message(ctx context.Context, socket string, message []byte) {
	deadline := time.Now().Add(timeout)

	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
	defer cancel()

	dialer := net.Dialer{}

	connection, dialErr := dialer.DialUnix(
		ctx,
		"unix",
		nil,
		&net.UnixAddr{Name: socket, Net: "unix"},
	)
	if dialErr != nil {
		log.Error().
			Str("socket", socket).
			Err(dialErr).
			Msg("failed to execute custom action")

		return
	}

	defer connection.Close()

	deadlineErr := connection.SetWriteDeadline(deadline)
	if deadlineErr != nil {
		log.Error().
			Str("socket", socket).
			Err(deadlineErr).
			Msg("failed to set write deadline")

		return
	}

	_, writeErr := connection.Write(message)
	if writeErr != nil {
		log.Error().
			Str("socket", socket).
			Err(writeErr).
			Msg("failed to write message to socket")

		return
	}
}

func ParseMessage(message []byte) (IPCMessage, error) {
	var msg IPCMessage

	err := json.Unmarshal(message, &msg)

	return msg, err
}
