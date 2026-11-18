package secretservice

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"

	_ "modernc.org/sqlite" // the "sqlite" driver
)

// store keeps the items in sqlite, in the schema - attributes as JSON -
// every version of the guard has used, so a project's existing database
// carries over.
//
// WAL mode plus a busy timeout so that concurrent sandboxes of the same
// project don't corrupt or deadlock on each other.
type store struct {
	mu sync.Mutex
	db *sql.DB
}

type row struct {
	id          int64
	attributes  map[string]string
	contentType string
	secret      []byte
}

func openStore(path string) (*store, error) {
	// Created at 0600 here, since sqlite would make it 0644 under the usual
	// umask - world-readable, for a file of plaintext credentials (gh's
	// OAuth token among them). O_CREAT's mode is ignored when the file
	// already exists, hence the chmod for databases created before. SQLite
	// gives the -wal and -shm sidecars the database file's own mode, so
	// this covers those too.
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
	return &store{db: db}, nil
}

// rows returns every item whose attributes parse.
func (s *store) rows() ([]row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rowsLocked()
}

func (s *store) rowsLocked() ([]row, error) {
	rs, err := s.db.Query("SELECT id, attributes, content_type, secret FROM items")
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []row
	for rs.Next() {
		var r row
		var attrs string
		if err := rs.Scan(&r.id, &attrs, &r.contentType, &r.secret); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(attrs), &r.attributes) != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

// upsert inserts an item, or with replace updates the one with exactly
// these attributes in place; its id.
func (s *store) upsert(label string, attrs map[string]string, contentType string, secret []byte, replace bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if replace {
		rows, err := s.rowsLocked()
		if err != nil {
			return 0, err
		}
		for _, r := range rows {
			if maps.Equal(r.attributes, attrs) {
				_, err := s.db.Exec("UPDATE items SET label = ?, content_type = ?, secret = ? WHERE id = ?",
					label, contentType, secret, r.id)
				return r.id, err
			}
		}
	}
	res, err := s.db.Exec("INSERT INTO items (label, attributes, content_type, secret) VALUES (?, ?, ?, ?)",
		label, pythonJSON(attrs), contentType, secret)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// get returns an item's content type and secret; sql.ErrNoRows if it's gone.
func (s *store) get(id int64) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var contentType string
	var secret []byte
	err := s.db.QueryRow("SELECT content_type, secret FROM items WHERE id = ?", id).Scan(&contentType, &secret)
	return contentType, secret, err
}

func (s *store) delete(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM items WHERE id = ?", id)
	return err
}

// pythonJSON writes attrs as Python's json.dumps(attrs, sort_keys=True) did,
// byte for byte, so rows look the same whichever version wrote them.
func pythonJSON(attrs map[string]string) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessCodePoint(keys[i], keys[j]) })
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		writePythonString(&b, k)
		b.WriteString(": ")
		writePythonString(&b, attrs[k])
	}
	b.WriteByte('}')
	return b.String()
}

// lessCodePoint orders as Python compares str: by code point.
func lessCodePoint(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

// writePythonString writes s as an ASCII-only JSON string.
func writePythonString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r > 0x7e && r < 0x10000:
			fmt.Fprintf(b, `\u%04x`, r)
		case r >= 0x10000:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}
