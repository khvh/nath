package migration

import (
  "database/sql"
  "embed"
	
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

func Migrate(command string, dbType string, migrations embed.FS, db *sql.DB) {
  goose.SetBaseFS(migrations)

  if err := goose.SetDialect(dbType); err != nil {
    log.Panic().Err(err).Send()
  }

  if err := goose.Run(command, db, "migrations"); err != nil {
    log.Panic().Err(err).Send()
  }
}