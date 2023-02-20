package migration

import (
	"database/sql"
	"embed"

	_ "github.com/glebarez/go-sqlite" // for sqlite
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // for postgres
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog/log"
)

// DBType ...
type DBType string

// DB Types
const (
	DialectSQLite     string = "sqlite3"
	DialectPostgreSQL string = "postgres"
)

// Init migrations
func Init(migrations embed.FS, args []string, dbType string, dsn string) {
	db, err := sqlx.Open(dbType, dsn)
	if err != nil {
		log.Panic().Err(err).Send()
	}

	if len(args) > 0 {
		migrate(args[0], dbType, migrations, db.DB)
	}
}

func migrate(command string, dbType string, migrations embed.FS, db *sql.DB) {
	goose.SetBaseFS(migrations)

	if err := goose.SetDialect(dbType); err != nil {
		log.Panic().Err(err).Send()
	}

	if err := goose.Run(command, db, "migrations"); err != nil {
		log.Panic().Err(err).Send()
	}
}