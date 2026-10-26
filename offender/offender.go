package offender

import (
	"encoding/json"
	"time"

	"gitlab.com/secban/secban-agent/entry"
)

type Offender struct {
	IP          string        `json:"ip"`
	Timestamp   time.Time     `json:"timestamp"`
	Entries     []entry.Entry `json:"entries"`
	ReportCount int           `json:"report_count"`
	BanCount    int           `json:"ban_count"`
}

func (o Offender) String() string {
	b, err := json.Marshal(o)
	if err != nil {
		return ""
	}

	return string(b)
}
