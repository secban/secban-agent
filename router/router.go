package router

import (
	"net/http"

	"gitlab.com/thequietbot/secban/secban-agent/handler/ban"
	"gitlab.com/thequietbot/secban/secban-agent/handler/ping"
	"gitlab.com/thequietbot/secban/secban-agent/handler/report"
	"gitlab.com/thequietbot/secban/secban-agent/handler/status"
)

func NewRouter() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/ping", ping.Handler)
	mux.HandleFunc("/report/{ip}/{rule}", report.Handler)
	mux.HandleFunc("/ban/{ip}/{rule}", ban.Handler)
	mux.HandleFunc("/status/{ip}", status.Handler)

	return mux
}
