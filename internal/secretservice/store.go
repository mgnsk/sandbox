package secretservice

import (
	"database/sql"
	"encoding/json/v2"
	"maps"
	"os"
	"sync"

	_ "modernc.org/sqlite" // The "sqlite" driver.
)

// Store keeps the items in sqlite, attributes as a JSON object.
//
// WAL mode plus a busy timeout so that concurrent sandboxes of the same
// project don't corrupt or deadlock on each other.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

type storedItem struct {
	id         int64
	attributes map[string]string
}

// OpenStore opens the database at path, creating it.
func OpenStore(path string) (*Store, error) {
	// Created at 0600 here, since sqlite would make it 0644 under the usual
	// umask - world-readable, for a file of plaintext credentials (gh's
	// OAuth token among them). O_CREAT's mode is ignored when the file
	// already exists, hence the chmod. SQLite gives the -wal and -shm
	// sidecars the database file's own mode, so this covers those too.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		label TEXT NOT NULL,
		attributes TEXT NOT NULL,
		content_type TEXT NOT NULL,
		secret BLOB NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// items lists every item whose attributes parse.
func (s *Store) items() ([]storedItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.itemsLocked()
}

func (s *Store) itemsLocked() ([]storedItem, error) {
	rows, err := s.db.Query("SELECT id, attributes FROM items")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storedItem
	for rows.Next() {
		var it storedItem
		var attrs []byte
		if err := rows.Scan(&it.id, &attrs); err != nil {
			return nil, err
		}
		if json.Unmarshal(attrs, &it.attributes) == nil {
			out = append(out, it)
		}
	}
	return out, rows.Err()
}

// put inserts an item, or with replace updates the one with exactly these
// attributes in place; its id.
func (s *Store) put(label string, attrs map[string]string, contentType string, secret []byte, replace bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if replace {
		items, err := s.itemsLocked()
		if err != nil {
			return 0, err
		}
		for _, it := range items {
			if maps.Equal(it.attributes, attrs) {
				_, err := s.db.Exec("UPDATE items SET label = ?, content_type = ?, secret = ? WHERE id = ?",
					label, contentType, secret, it.id)
				return it.id, err
			}
		}
	}
	data, err := json.Marshal(attrs, json.Deterministic(true))
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec("INSERT INTO items (label, attributes, content_type, secret) VALUES (?, ?, ?, ?)",
		label, string(data), contentType, secret)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// get returns an item's content type and secret; sql.ErrNoRows if it's gone.
func (s *Store) get(id int64) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var contentType string
	var secret []byte
	err := s.db.QueryRow("SELECT content_type, secret FROM items WHERE id = ?", id).Scan(&contentType, &secret)
	return contentType, secret, err
}

func (s *Store) delete(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM items WHERE id = ?", id)
	return err
}
