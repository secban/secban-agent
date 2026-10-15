package report

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/rs/zerolog/log"
	"gitlab.com/secban/secban-agent/dispatcher"
)

const (
	numArgs           = 3
	messageQueryParam = "message"
	messageMaxLength  = 2048
)

const parseRegExp = `^/report/(?P<ip>[^/]+)/(?P<rule>[^/]+)$`

var parseRegExpCompiled = regexp.MustCompile(parseRegExp)

func Handler(w http.ResponseWriter, r *http.Request) {
	log.Debug().
		Str("handler", "report").
		Str("path", r.URL.Path).
		Str("method", r.Method).
		Msg("received report request")

	submatches := parseRegExpCompiled.FindStringSubmatch(r.URL.Path)
	if len(submatches) < numArgs {
		http.Error(w, "invalid report path", http.StatusBadRequest)
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
		Str("handler", "report").
		Str("ip", ip).
		Str("rule", rule).
		Str("message", message).
		Msg("handling report request")

	allowed, reportErr := dispatcher.Report(r.Context(), ip, rule, message)
	if reportErr != nil {
		log.Warn().
			Str("handler", "report").
			Str("ip", ip).
			Str("rule", rule).
			Err(reportErr).
			Msg("report rejected")
		http.Error(w, reportErr.Error(), http.StatusBadRequest)

		return
	}

	w.WriteHeader(http.StatusOK)

	response := map[string]string{"message": "reported", "ip": ip, "rule": rule}
	if allowed {
		response = map[string]string{"message": "ignored", "ip": ip, "rule": "ip allowed"}
	}

	encodeErr := json.NewEncoder(w).Encode(response)
	if encodeErr != nil {
		log.Error().
			Str("handler", "report").
			Err(encodeErr).
			Msg("failed to encode report response")
		http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
	}
}
