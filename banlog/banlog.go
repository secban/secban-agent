package banlog

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
	"gitlab.com/secban/secban-agent/db"
	"gitlab.com/secban/secban-agent/offender"
)

const databaseConnectionErrorMessage = "Failed to get database connection"

type Entry struct {
	BanTime  time.Time
	IP       string
	Rule     string
	Events   string
	BanCount int
}

func Log(ctx context.Context, rule string, o offender.Offender) {
	log.Debug().
		Str("ip", o.IP).
		Str("rule", rule).
		Time("ban_time", o.Timestamp).
		Int("ban_count", o.BanCount).
		Msg("Logging ban for offender")

	marshalled, marshallErr := json.Marshal(o)
	if marshallErr != nil {
		log.Error().Err(marshallErr).Msg("Failed to marshal offender")
		return
	}

	database, err := db.DB(ctx)
	if err != nil {
		log.Error().Err(err).Msg(databaseConnectionErrorMessage)
		return
	}

	r, err := database.ExecContext(ctx, `
		INSERT OR REPLACE INTO bans (ip, rule, ban_time, ban_count, events)
		VALUES (?, ?, ?, ?, ?);
	`, o.IP, rule, o.Timestamp, o.BanCount, string(marshalled))
	if err != nil {
		log.Error().Interface("result", r).Err(err).Msg("Failed to insert ban into database")
	}
}

func Get(ctx context.Context, ip string) (*Entry, error) {
	database, initErr := db.DB(ctx)
	if initErr != nil {
		log.Error().Err(initErr).Msg(databaseConnectionErrorMessage)
		return nil, initErr
	}

	row := database.QueryRowContext(ctx, `
		SELECT ip, rule, ban_time, ban_count, events
		FROM bans
		WHERE ip = ?
		ORDER BY ban_time DESC
		LIMIT 1;
	`, ip)

	var entry Entry

	scanErr := row.Scan(&entry.IP, &entry.Rule, &entry.BanTime, &entry.BanCount, &entry.Events)
	if scanErr != nil {
		log.Error().Err(scanErr).Msg("Failed to scan ban entry from database")
		return nil, scanErr
	}

	return &entry, nil
}

func GetAllFrom(ctx context.Context, from time.Time) ([]*Entry, error) {
	return queryEntries(ctx, `
		SELECT ip, rule, ban_time, ban_count, events
		FROM bans
		WHERE ban_time >= ?
		ORDER BY ban_time DESC;
	`, from)
}

func CountSince(ctx context.Context, since time.Time) (int, error) {
	database, dbErr := db.DB(ctx)
	if dbErr != nil {
		log.Error().Err(dbErr).Msg(databaseConnectionErrorMessage)
		return 0, dbErr
	}

	row := database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM bans
		WHERE ban_time > ?;
	`, since)

	var count int

	scanErr := row.Scan(&count)
	if scanErr != nil {
		log.Error().Err(scanErr).Msg("Failed to scan ban count from database")
		return 0, scanErr
	}

	return count, nil
}

func GetSince(ctx context.Context, since time.Time) ([]*Entry, error) {
	return queryEntries(ctx, `
		SELECT ip, rule, ban_time, ban_count, events
		FROM bans
		WHERE ban_time > ?
		ORDER BY ban_time ASC;
	`, since)
}

func queryEntries(ctx context.Context, query string, args ...any) ([]*Entry, error) {
	database, dbErr := db.DB(ctx)
	if dbErr != nil {
		log.Error().Err(dbErr).Msg(databaseConnectionErrorMessage)
		return nil, dbErr
	}

	rows, queryErr := database.QueryContext(ctx, query, args...)
	if queryErr != nil {
		log.Error().Err(queryErr).Msg("Failed to query bans from database")
		return nil, queryErr
	}
	defer rows.Close()

	var entries []*Entry

	for rows.Next() {
		var entry Entry

		scanErr := rows.Scan(&entry.IP, &entry.Rule, &entry.BanTime, &entry.BanCount, &entry.Events)
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
