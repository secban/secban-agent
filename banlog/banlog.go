package banlog

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
	"gitlab.com/thequietbot/secban/secban-agent/db"
	"gitlab.com/thequietbot/secban/secban-agent/offender"
)

type Entry struct {
	IP     string
	Rule   string
	Ban    time.Time
	Events string
}

func Log(ctx context.Context, rule string, o offender.Offender) {
	log.Debug().
		Str("ip", o.IP).
		Str("rule", rule).
		Time("ban", o.Timestamp).
		Msg("Logging ban for offender")

	marshalled, marshallErr := json.Marshal(o)
	if marshallErr != nil {
		log.Error().Err(marshallErr).Msg("Failed to marshal offender")
		return
	}

	db, err := db.DB(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get database connection")
		return
	}

	r, err := db.ExecContext(ctx, `
		INSERT OR REPLACE INTO bans (ip, rule, ban, events)
		VALUES (?, ?, ?, ?);
	`, o.IP, rule, o.Timestamp, string(marshalled))
	if err != nil {
		log.Error().Interface("result", r).Err(err).Msg("Failed to insert ban into database")
	}
}

func Get(ctx context.Context, ip string) (*Entry, error) {
	db, initErr := db.DB(ctx)
	if initErr != nil {
		log.Error().Err(initErr).Msg("Failed to get database connection")
		return nil, initErr
	}

	row := db.QueryRowContext(ctx, `
		SELECT ip, rule, ban, events
		FROM bans
		WHERE ip = ?
		ORDER BY ban DESC
		LIMIT 1;
	`, ip)

	var entry Entry

	scanErr := row.Scan(&entry.IP, &entry.Rule, &entry.Ban, &entry.Events)
	if scanErr != nil {
		log.Error().Err(scanErr).Msg("Failed to scan ban entry from database")
		return nil, scanErr
	}

	return &entry, nil
}

func GetAllFrom(ctx context.Context, from time.Time) ([]*Entry, error) {
	db, initErr := db.DB(ctx)
	if initErr != nil {
		log.Error().Err(initErr).Msg("Failed to get database connection")
		return nil, initErr
	}

	rows, queryErr := db.QueryContext(ctx, `
		SELECT ip, rule, ban, events
		FROM bans
		WHERE ban >= ?
		ORDER BY ban DESC;
	`, from)
	if queryErr != nil {
		log.Error().Err(queryErr).Msg("Failed to query bans from database")
		return nil, queryErr
	}
	defer rows.Close()

	var entries []*Entry

	for rows.Next() {
		var entry Entry

		scanErr := rows.Scan(&entry.IP, &entry.Rule, &entry.Ban, &entry.Events)
		if scanErr != nil {
			log.Error().Err(scanErr).Msg("Failed to scan ban entry from database")
			return nil, scanErr
		}

		entries = append(entries, &entry)
	}

	if rows.Err() != nil {
		log.Error().Err(rows.Err()).Msg("Error occurred during rows iteration")
		return nil, rows.Err()
	}

	return entries, nil
}
