package lagoondb

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

func NewClientFromDB(db *sql.DB) *Client {
	return &Client{db: sqlx.NewDb(db, "mysql")}
}
