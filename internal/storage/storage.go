package storage

import (
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"

	milt "github.com/mail-cci/antispam/internal/milter"
)

// New opens a MySQL connection using the provided URL and limits the number of
// open connections.
func New(dbURL string, maxConns int) (*sql.DB, error) {
	db, err := sql.Open("mysql", dbURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxConns)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

// Store wraps a sql.DB to implement the milter.Store interface.
type Store struct{ DB *sql.DB }

// NewStore creates a Store using the provided DB.
func NewStore(db *sql.DB) *Store { return &Store{DB: db} }

// SaveEmail persists the email, its headers and attachments. It returns the
// generated email ID.
func (s *Store) SaveEmail(e *milt.Email) (int64, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	res, err := tx.Exec(`INSERT INTO emails (correlation_id, envelope_from, client_ip, helo, received_at, body)
        VALUES (?,?,?,?,?,?)`,
		e.ID(), e.From(), e.ClientAddr(), e.Helo(), time.Now(), e.Body())
	if err != nil {
		return 0, err
	}
	emailID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	for name, vals := range e.Headers() {
		for _, v := range vals {
			if _, err = tx.Exec(`INSERT INTO email_headers (email_id, name, value) VALUES (?,?,?)`,
				emailID, name, v); err != nil {
				return 0, err
			}
		}
	}

	for _, att := range e.Attachments() {
		if _, err = tx.Exec(`INSERT INTO email_attachments (email_id, filename, content_type, content) VALUES (?,?,?,?)`,
			emailID, att.Filename, att.ContentType, att.Data); err != nil {
			return 0, err
		}
	}

	return emailID, nil
}

// SaveSpamScore stores the results of a spam engine for a message.
func (s *Store) SaveSpamScore(emailID int64, engine string, score, threshold float64, isSpam bool) error {
	_, err := s.DB.Exec(`INSERT INTO spam_scores (email_id, engine, score, threshold, is_spam) VALUES (?,?,?,?,?)`,
		emailID, engine, score, threshold, isSpam)
	return err
}

// QuarantineEmail records that an email has been quarantined for the given reason.
func (s *Store) QuarantineEmail(emailID int64, reason string) error {
	_, err := s.DB.Exec(`INSERT INTO quarantine (email_id, reason, quarantined_at) VALUES (?,?,?)`,
		emailID, reason, time.Now())
	return err
}
