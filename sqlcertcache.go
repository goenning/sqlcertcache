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

	"golang.org/x/crypto/acme/autocert"
)

// Making sure that we're adhering to the autocert.Cache interface.
var _ autocert.Cache = (*Cache)(nil)

// Cache provides a SQL backend to the autocert cache.
type Cache struct {
	conn      *sql.DB
	tableName string
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

	return &Cache{conn, tableName}, nil
}

// Get returns a certificate data for the specified key.
// If there's no such key, Get returns ErrCacheMiss.
func (c Cache) Get(ctx context.Context, key string) ([]byte, error) {
	var data []byte
	row := c.conn.QueryRowContext(ctx, fmt.Sprintf(`SELECT data FROM %s`, c.tableName))
	err := row.Scan(&data)
	if err == sql.ErrNoRows {
		return nil, autocert.ErrCacheMiss
	}
	return data, err
}

// Put stores the data in the cache under the specified key.
func (c Cache) Put(ctx context.Context, key string, data []byte) error {
	query := fmt.Sprintf(`
	INSERT INTO %s (key, data)
	VALUES ($1, $2) ON CONFLICT (key)
	DO UPDATE SET data = $2`, c.tableName)
	_, err := c.conn.ExecContext(ctx, query, key, data)
	if err != nil {
		return err
	}
	return nil
}

// Delete removes a certificate data from the cache under the specified key.
// If there's no such key in the cache, Delete returns nil.
func (c Cache) Delete(ctx context.Context, key string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE key = $1`, c.tableName)
	_, err := c.conn.ExecContext(ctx, query, key)
	if err != nil {
		return err
	}
	return nil
}
