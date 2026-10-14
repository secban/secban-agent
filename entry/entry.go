package entry

import "time"

type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}
