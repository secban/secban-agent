package action

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/secban/secban-agent/offender"
)

const timeout = 20 * time.Second

type ActionArgs struct {
	IP       string
	Rule     string
	Actions  []string
	Offender offender.Offender
}

func ExecuteCustomAction(ctx context.Context, args ActionArgs) {
	if len(args.Actions) == 0 {
		log.Warn().
			Str("ip", args.IP).
			Str("rule", args.Rule).
			Msg("no custom actions to execute")

		return
	}

	offenderJSON, marshallErr := json.Marshal(args.Offender)
	if marshallErr != nil {
		log.Error().
			Str("ip", args.IP).
			Str("rule", args.Rule).
			Err(marshallErr).
			Msg("failed to marshal offender to JSON")

		return
	}

	baseArgs := []string{args.IP, args.Rule, string(offenderJSON)}

	for _, actionPath := range args.Actions {
		if actionPath == "" {
			continue
		}

		go func(actionPath string) {
			log.Debug().
				Str("ip", args.IP).
				Str("rule", args.Rule).
				Str("action", actionPath).
				Msg("executing custom action")

			runCtx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
			defer cancel()

			cmd := exec.CommandContext(runCtx, actionPath, baseArgs...)

			if zerolog.GlobalLevel() >= zerolog.DebugLevel {
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
			}

			err := cmd.Run()
			if err != nil {
				log.Error().
					Str("ip", args.IP).
					Str("rule", args.Rule).
					Str("action", actionPath).
					Err(err).
					Msg("failed to execute custom action")
			}
		}(actionPath)
	}
}
