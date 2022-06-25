package log

import (
	"io"
	"os"

	console "github.com/mattn/go-isatty"
	"github.com/rs/zerolog"

	"github.com/corpix/gdk/errors"
)

type (
	Level   = zerolog.Level
	Logger  = zerolog.Logger
	Event   = zerolog.Event
	Context = zerolog.Context
)

const (
	LevelTrace = zerolog.TraceLevel
	LevelDebug = zerolog.DebugLevel
	LevelInfo  = zerolog.InfoLevel
	LevelWarn  = zerolog.WarnLevel
	LevelError = zerolog.ErrorLevel
	LevelPanic = zerolog.PanicLevel
	LevelFatal = zerolog.FatalLevel
)

var log Logger

func Debug() *Event                                { return log.Debug() }
func Err(err error) *Event                         { return log.Err(err) }
func Error() *Event                                { return log.Error() }
func Fatal() *Event                                { return log.Fatal() }
func Info() *Event                                 { return log.Info() }
func Log() *Event                                  { return log.Log() }
func Panic() *Event                                { return log.Panic() }
func Print(v ...interface{})                       { log.Print(v...) }
func Printf(format string, v ...interface{})       { log.Printf(format, v...) }
func Trace() *Event                                { return log.Trace() }
func UpdateContext(update func(c Context) Context) { log.UpdateContext(update) }
func Warn() *Event                                 { return log.Warn() }
func WithLevel(level Level) *Event                 { return log.WithLevel(level) }
func With() Context                                { return log.With() }

//

type Config struct {
	Level string `yaml:"level"`
}

func (c *Config) Default() {
	if c.Level == "" {
		c.Level = LevelInfo.String()
	}
}

//

func New(level string) (Logger, error) {
	var (
		output = os.Stdout

		log      Logger
		logLevel Level
		err      error
		w        io.Writer
	)

	if console.IsTerminal(output.Fd()) {
		w = zerolog.ConsoleWriter{Out: output}
	} else {
		w = output
	}

	if level == "" {
		level = LevelInfo.String()
	}
	logLevel, err = zerolog.ParseLevel(level)
	if err != nil {
		return log, errors.Wrapf(err, "failed to parse logging level %q", level)
	}

	log = zerolog.New(w).With().
		Timestamp().Logger().
		Level(logLevel)

	return log, nil
}

func Init(level string) error {
	l, err := New(level)
	if err != nil {
		return err
	}

	log = l

	return nil
}
