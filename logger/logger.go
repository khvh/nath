package logger

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init logger for dev or prod
func Init(level int, devMode bool) {
	if devMode {
		zerolog.SetGlobalLevel(zerolog.Level(level))
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		zerolog.SetGlobalLevel(zerolog.Level(level))
	}
}
