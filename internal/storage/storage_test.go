package storage

import (
	"net"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	milt "github.com/mail-cci/antispam/internal/milter"
	"go.uber.org/zap"
)

func TestSaveEmail(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	e := milt.MailProcessor(zap.NewNop(), nil)
	e.Connect("host", "tcp", 25, net.ParseIP("1.2.3.4"), nil)
	e.Helo("mx.example", nil)
	e.MailFrom("alice@example.com", nil)
	e.Header("Subject", "Test", nil)
	e.BodyChunk([]byte("body"), nil)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO emails").
		WithArgs(e.ID(), e.From(), e.ClientAddr(), e.Helo(), sqlmock.AnyArg(), e.Body()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO email_headers").
		WithArgs(1, "Subject", "Test").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	store := NewStore(db)
	id, err := store.SaveEmail(e)
	if err != nil {
		t.Fatalf("SaveEmail returned error: %v", err)
	}
	if id != 1 {
		t.Errorf("expected id 1 got %d", id)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestSaveSpamScore(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO spam_scores").
		WithArgs(1, "engine", 5.0, 4.0, true).
		WillReturnResult(sqlmock.NewResult(1, 1))

	store := NewStore(db)
	if err := store.SaveSpamScore(1, "engine", 5.0, 4.0, true); err != nil {
		t.Fatalf("SaveSpamScore error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestQuarantineEmail(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO quarantine").
		WithArgs(1, "reason", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	store := NewStore(db)
	if err := store.QuarantineEmail(1, "reason"); err != nil {
		t.Fatalf("QuarantineEmail error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
