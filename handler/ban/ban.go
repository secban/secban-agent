package ban

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/rs/zerolog/log"
	"gitlab.com/thequietbot/secban/secban-agent/dispatcher"
)

const (
	numArgs           = 3
	messageQueryParam = "message"
	messageMaxLength  = 2048
)

const parseRegExp = `^/ban/(?P<ip>[^/]+)/(?P<rule>[^/]+)$`

var parseRegExpCompiled = regexp.MustCompile(parseRegExp)

func Handler(w http.ResponseWriter, r *http.Request) {
	log.Debug().
		Str("handler", "ban").
		Str("path", r.URL.Path).
		Str("method", r.Method).
		Msg("received manual ban request")

	submatches := parseRegExpCompiled.FindStringSubmatch(r.URL.Path)
	if len(submatches) < numArgs {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ip := submatches[1]
	rule := submatches[2]
	message := r.URL.Query().Get(messageQueryParam)

	if len(message) > messageMaxLength {
		http.Error(w, "message too long", http.StatusBadRequest)
		return
	}

	log.Debug().
		Str("handler", "ban").
		Str("ip", ip).
		Str("rule", rule).
		Str("message", message).
		Msg("handling manual ban request")

	allowed, actErr := dispatcher.Ban(r.Context(), ip, rule, message)
	if actErr != nil {
		log.Warn().
			Str("handler", "ban").
			Str("ip", ip).
			Str("rule", rule).
			Err(actErr).
			Msg("ban failed")
		http.Error(w, actErr.Error(), http.StatusBadRequest)

		return
	}

	w.WriteHeader(http.StatusOK)

	response := map[string]string{"message": "banned", "ip": ip, "rule": rule}
	if allowed {
		response = map[string]string{"message": "ignored", "ip": ip, "rule": "ip allowed"}
	}

	encodeErr := json.NewEncoder(w).Encode(response)
	if encodeErr != nil {
		log.Error().
			Str("handler", "ban").
			Err(encodeErr).
			Msg("failed to encode ban response")
		http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
	}
}
