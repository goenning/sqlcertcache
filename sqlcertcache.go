// Package sqlcertcache implements an autocert.Cache to store certificate data within a SQL Database
//
// See https://godoc.org/golang.org/x/crypto/acme/autocert
package sqlcertcache

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

// Making sure that we're adhering to the autocert.Cache interface.
var _ autocert.Cache = (*Cache)(nil)

// Cache provides a SQL backend to the autocert cache.
type Cache struct {
	conn        *sql.DB
	certs       map[string][]byte
	certsMu     sync.RWMutex
	getQuery    string
	insertQuery string
	updateQuery string
	deleteQuery string
}

// New creates an cache instance that can be used with autocert.Cache.
// It returns any errors that could happen while connecting to SQL.
func New(conn *sql.DB, tableName string) (*Cache, error) {
	if strings.TrimSpace(tableName) == "" {
		return nil, errors.New("tableName must not be empty")
	}

	_, err := conn.Exec(fmt.Sprintf(`create table if not exists %s (
		key  varchar(400) not null primary key, 
		data bytea not null
	);`, tableName))
	if err != nil {
		return nil, err
	}

	return &Cache{
		conn:        conn,
		certs:       make(map[string][]byte),
		getQuery:    fmt.Sprintf(`SELECT data FROM %s`, tableName),
		insertQuery: fmt.Sprintf(`INSERT INTO %s (key, data) VALUES($1, $2)`, tableName),
		updateQuery: fmt.Sprintf(`UPDATE %s SET data = $2 WHERE key = $1`, tableName),
		deleteQuery: fmt.Sprintf(`DELETE FROM %s WHERE key = $1`, tableName),
	}, nil
}

// Get returns a certificate data for the specified key.
// If there's no such key, Get returns ErrCacheMiss.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	c.certsMu.RLock()
	defer c.certsMu.RUnlock()

	data, ok := c.certs[key]
	if ok {
		return data, nil
	}

	row := c.conn.QueryRowContext(ctx, c.getQuery)
	err := row.Scan(&data)
	if err == sql.ErrNoRows {
		return nil, autocert.ErrCacheMiss
	}
	return data, err
}

// Put stores the data in the cache under the specified key.
func (c *Cache) Put(ctx context.Context, key string, data []byte) error {
	c.certsMu.Lock()
	defer c.certsMu.Unlock()

	result, err := c.conn.ExecContext(ctx, c.updateQuery, key, data)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		_, err := c.conn.ExecContext(ctx, c.insertQuery, key, data)
		if err != nil {
			return err
		}
	}

	c.certs[key] = data
	return nil
}

// Delete removes a certificate data from the cache under the specified key.
// If there's no such key in the cache, Delete returns nil.
func (c *Cache) Delete(ctx context.Context, key string) error {
	c.certsMu.Lock()
	defer c.certsMu.Unlock()

	_, ok := c.certs[key]
	if ok {
		delete(c.certs, key)
	}

	_, err := c.conn.ExecContext(ctx, c.deleteQuery, key)
	if err != nil {
		return err
	}
	return nil
}
