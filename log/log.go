package log

import (
	"io"
	"os"

	console "github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"

	"github.com/corpix/gdk/errors"
)

type (
	Level   = zerolog.Level
	Logger  = zerolog.Logger
	Option  func(*Logger)
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

var Default Logger

func Debug() *Event                                { return Default.Debug() }
func Err(err error) *Event                         { return Default.Err(err) }
func Error() *Event                                { return Default.Error() }
func Fatal() *Event                                { return Default.Fatal() }
func Info() *Event                                 { return Default.Info() }
func Log() *Event                                  { return Default.Log() }
func Panic() *Event                                { return Default.Panic() }
func Print(v ...interface{})                       { Default.Print(v...) }
func Printf(format string, v ...interface{})       { Default.Printf(format, v...) }
func Trace() *Event                                { return Default.Trace() }
func UpdateContext(update func(c Context) Context) { Default.UpdateContext(update) }
func Warn() *Event                                 { return Default.Warn() }
func WithLevel(level Level) *Event                 { return Default.WithLevel(level) }
func With() Context                                { return Default.With() }

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

func New(level string, options ...Option) (Logger, error) {
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

	for _, option := range options {
		option(&log)
	}

	return log, nil
}

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
}

func Init(level string, options ...Option) error {
	l, err := New(level, options...)
	if err != nil {
		return err
	}

	Default = l

	return nil
}
