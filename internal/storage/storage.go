package storage

import (
	"context"
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

type Storage struct {
	DB *sql.DB
}

func New(dsn string, maxConns int) (*Storage, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	return &Storage{DB: db}, nil
}

func (s *Storage) Close() error {
	return s.DB.Close()
}

func (s *Storage) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS emails (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            correlation_id VARCHAR(36) NOT NULL,
            from_address VARCHAR(255),
            helo VARCHAR(255),
            host VARCHAR(255),
            port VARCHAR(10),
            addr VARCHAR(45),
            body TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
		`CREATE TABLE IF NOT EXISTS email_headers (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            email_id BIGINT,
            name VARCHAR(255),
            value TEXT,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )`,
		`CREATE TABLE IF NOT EXISTS email_attachments (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            email_id BIGINT,
            filename TEXT,
            content_type VARCHAR(255),
            data LONGBLOB,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )`,
		`CREATE TABLE IF NOT EXISTS spam_scores (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            email_id BIGINT,
            score FLOAT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )`,
		`CREATE TABLE IF NOT EXISTS quarantine (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            email_id BIGINT,
            reason TEXT,
            quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            released_at TIMESTAMP NULL,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )`,
	}
	for _, stmt := range stmts {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Storage) SaveEmail(ctx context.Context, e *milt.Email) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO emails (correlation_id, from_address, helo, host, port, addr, body)
         VALUES (?,?,?,?,?,?,?)`,
		e.ID(), e.From(), e.Helo(), e.Client()["host"], e.Client()["port"], e.Client()["addr"], e.Body(),
	)
	if err != nil {
		tx.Rollback()
		return err
	}
	emailID, err := res.LastInsertId()
	if err != nil {
		tx.Rollback()
		return err
	}
	for name, values := range e.Headers() {
		for _, v := range values {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO email_headers (email_id, name, value) VALUES (?,?,?)`,
				emailID, name, v,
			); err != nil {
				tx.Rollback()
				return err
			}
		}
	}
	for _, att := range e.Attachments() {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO email_attachments (email_id, filename, content_type, data)
             VALUES (?,?,?,?)`,
			emailID, att.Filename, att.ContentType, att.Data,
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
