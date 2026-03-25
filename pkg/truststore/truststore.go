package truststore

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

type TrustStore struct {
	db *sql.DB
}

func New(dbPath string) (*TrustStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open trust store: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS trusted_senders (
		email TEXT PRIMARY KEY NOT NULL,
		added_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &TrustStore{db: db}, nil
}

// IsTrusted checks if an email address is trusted, either by exact match or domain match.
func (ts *TrustStore) IsTrusted(email string) (bool, error) {
	email = strings.ToLower(email)

	// Check exact match
	var exists int
	err := ts.db.QueryRow("SELECT 1 FROM trusted_senders WHERE email = ?", email).Scan(&exists)
	if err == nil {
		return true, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}

	// Check domain match
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		domain := "@" + parts[1]
		err = ts.db.QueryRow("SELECT 1 FROM trusted_senders WHERE email = ?", domain).Scan(&exists)
		if err == nil {
			return true, nil
		}
		if err != sql.ErrNoRows {
			return false, err
		}
	}

	return false, nil
}

// Add inserts an email address or @domain into the trust store. Idempotent.
func (ts *TrustStore) Add(email string) error {
	email = strings.ToLower(email)
	_, err := ts.db.Exec("INSERT OR IGNORE INTO trusted_senders (email) VALUES (?)", email)
	return err
}

// Remove deletes an email address or @domain from the trust store. Idempotent.
func (ts *TrustStore) Remove(email string) error {
	email = strings.ToLower(email)
	_, err := ts.db.Exec("DELETE FROM trusted_senders WHERE email = ?", email)
	return err
}

func (ts *TrustStore) Close() error {
	return ts.db.Close()
}
