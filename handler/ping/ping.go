package ping

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	log.Debug().
		Str("handler", "ping").
		Str("method", r.Method).
		Msg("ping received")

	w.WriteHeader(http.StatusOK)

	encodeErr := json.NewEncoder(w).Encode("pong")
	if encodeErr != nil {
		log.Error().
			Str("handler", "ping").
			Err(encodeErr).
			Msg("failed to encode ping response")
		http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
	}
}
