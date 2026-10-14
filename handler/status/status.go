package status

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/rs/zerolog/log"
	"gitlab.com/thequietbot/secban/secban-agent/dispatcher"
)

const numArgs = 2

const parseRegExp = `^/status/(?P<ip>[^/]+)$`

var parseRegExpCompiled = regexp.MustCompile(parseRegExp)

func Handler(w http.ResponseWriter, r *http.Request) {
	log.Debug().
		Str("handler", "status").
		Str("path", r.URL.Path).
		Str("method", r.Method).
		Msg("received status request")

	submatches := parseRegExpCompiled.FindStringSubmatch(r.URL.Path)
	if len(submatches) < numArgs {
		http.Error(w, "invalid status path", http.StatusBadRequest)
		return
	}

	ip := submatches[1]

	log.Debug().
		Str("handler", "status").
		Str("ip", ip).
		Msg("handling status request")

	offender, getErr := dispatcher.Get(r.Context(), ip)
	if getErr != nil {
		log.Debug().
			Str("handler", "status").
			Str("ip", ip).
			Err(getErr).
			Msg("offender not found")
		http.Error(w, getErr.Error(), http.StatusBadRequest)

		return
	}

	w.WriteHeader(http.StatusOK)

	response, marshalErr := json.Marshal(offender)
	if marshalErr != nil {
		log.Error().
			Str("handler", "status").
			Str("ip", ip).
			Err(marshalErr).
			Msg("failed to marshal offender")
		http.Error(w, marshalErr.Error(), http.StatusInternalServerError)

		return
	}

	_, encodeErr := w.Write(response)
	if encodeErr != nil {
		log.Error().
			Str("handler", "status").
			Str("ip", ip).
			Err(encodeErr).
			Msg("failed to write status response")
		http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
	}
}
