package cli

import (
	"fmt"
	"os"

	"github.com/corpix/gdk/config"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/metrics"

	cli "github.com/urfave/cli/v2"
)

type (
	BoolFlag         = cli.BoolFlag
	Command          = cli.Command
	Commands         = cli.Commands
	Context          = cli.Context
	DurationFlag     = cli.DurationFlag
	Flag             = cli.Flag
	Flags            = []Flag
	Float64Flag      = cli.Float64Flag
	Float64SliceFlag = cli.Float64SliceFlag
	GenericFlag      = cli.GenericFlag
	Int64Flag        = cli.Int64Flag
	Int64SliceFlag   = cli.Int64SliceFlag
	IntFlag          = cli.IntFlag
	IntSliceFlag     = cli.IntSliceFlag
	PathFlag         = cli.PathFlag
	StringFlag       = cli.StringFlag
	StringSliceFlag  = cli.StringSliceFlag
	TimestampFlag    = cli.TimestampFlag
	Uint64Flag       = cli.Uint64Flag
	UintFlag         = cli.UintFlag

	App        = cli.App
	BeforeFunc = cli.BeforeFunc
	AfterFunc  = cli.AfterFunc
	ActionFunc = cli.ActionFunc
	Action     = func(*Context) error

	Config          = config.Config
	ConfigContainer = config.Container

	Cli struct {
		*App
		Config *ConfigContainer
	}

	Option func(*Cli)
)

//

func WithComposition(options ...Option) Option {
	return func(c *Cli) {
		for _, option := range options {
			option(c)
		}
	}
}

//

func WithName(name string) Option {
	return func(c *Cli) {
		c.Name = name
	}
}

func WithDescription(desc string) Option {
	return func(c *Cli) {
		c.Description = desc
	}
}

func WithUsage(usage string) Option {
	return func(c *Cli) {
		c.Usage = usage
	}
}

func WithVersion(version string) Option {
	return func(c *Cli) {
		c.Version = version
	}
}

func WithConfig(cfg Config) Option {
	return func(c *Cli) {
		c.Config = config.New(cfg)
	}
}

//

func WithFlags(flags Flags) Option {
	return func(c *Cli) {
		c.Flags = append(c.Flags, flags...)
	}
}

func WithCommands(commands Commands) Option {
	return func(c *Cli) {
		c.Commands = append(c.Commands, commands...)
	}
}

//

func ActionChain(current Action, next Action) Action {
	if current != nil {
		return func(ctx *Context) error {
			err := current(ctx)
			if err != nil {
				return err
			}
			return next(ctx)
		}
	}
	return next
}

func WithBefore(fn BeforeFunc) Option {
	return func(c *Cli) {
		c.Before = ActionChain(c.Before, fn)
	}
}
func WithAfter(fn AfterFunc) Option {
	return func(c *Cli) {
		c.After = ActionChain(c.After, fn)
	}
}
func WithAction(fn ActionFunc) Option {
	return func(c *Cli) {
		c.Action = ActionChain(c.Action, fn)
	}
}

//

func ConfigFromContext(ctx *Context, cfg Config, unmarshaler config.Unmarshaler) error {
	paths := ctx.StringSlice("config")
	sources := make([]config.Option, len(paths))

	for n, path := range paths {
		sources[n] = config.FromFile(path, unmarshaler)
	}

	_, err := config.Load(cfg, sources...)
	if err != nil {
		return err
	}
	return nil
}

func WithConfigTools(cfg Config, unmarshaler config.Unmarshaler, marshaler config.Marshaler) Option {
	return WithComposition(
		WithConfig(cfg),
		WithBefore(func(ctx *Context) error {
			err := ConfigFromContext(ctx, cfg, unmarshaler)
			if err != nil {
				return err
			}

			return config.Postprocess(
				cfg,
				config.WithDefaults(),
				config.WithExpansion(),
				config.WithValidation(),
			)
		}),
		func(c *Cli) {
			c.Flags = append(c.Flags, &StringSliceFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "path to application configuration file",
				Value:   cli.NewStringSlice("config.yml"),
			})

			commands := Commands{}

			if _, ok := c.Config.Unwrap().(config.Defaultable); ok {
				commands = append(commands, &Command{
					Name:    "show-default",
					Aliases: []string{"sd"},
					Usage:   "Show default configuration",
					Action: func(ctx *Context) error {
						err := config.Postprocess(
							c.Config.EmptyClone(),
							config.WithDefaults(),
						)
						if err != nil {
							return err
						}
						return config.ToWriter(os.Stdout, marshaler)(cfg)
					},
				})
			}

			if _, ok := c.Config.Unwrap().(config.Validatable); ok {
				commands = append(commands, &Command{
					Name:    "validate",
					Aliases: []string{"v"},
					Usage:   "Validate configuration and exit",
					Action: func(ctx *Context) error {
						err := ConfigFromContext(ctx, cfg, unmarshaler)
						if err != nil {
							return err
						}

						err = config.Postprocess(
							cfg,
							config.WithDefaults(),
							config.WithExpansion(),
							config.WithValidation(),
						)
						if err != nil {
							return err
						}

						fmt.Println("configuration is valid")

						return nil
					},
				})
			}

			commands = append(commands, &Command{
				Name:    "show",
				Aliases: []string{"s"},
				Usage:   "Show current configuration",
				Action: func(ctx *Context) error {
					err := ConfigFromContext(ctx, cfg, unmarshaler)
					if err != nil {
						return err
					}

					err = config.Postprocess(
						cfg,
						config.WithDefaults(),
						config.WithExpansion(),
					)
					if err != nil {
						return err
					}
					return config.ToWriter(os.Stdout, marshaler)(cfg)
				},
			})

			c.Commands = append(c.Commands, &Command{
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "Configuration tools",
				Subcommands: commands,
			})
		},
	)
}

func WithLogTools(cfg func() *log.Config, options ...log.Option) Option {
	return WithComposition(
		WithFlags(Flags{
			&StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "logging level (debug, info, warn, error)",
			},
		}),
		func(c *Cli) {
			WithBefore(func(ctx *Context) error {
				level := ctx.String("log-level")
				if level == "" {
					level = cfg().Level
				}

				return log.Init(level, options...)
			})(c)
		},
	)
}

func WithHttpTools(cfg func() *http.Config, router *http.Router, options ...http.Option) Option {
	return func(c *Cli) {
		c.Commands = append(c.Commands, &Command{
			Name:    "http",
			Aliases: []string{"ht"},
			Usage:   "HTTP server tools",
			Flags: Flags{
				&StringFlag{
					Name:    "address",
					Aliases: []string{"a"},
					Usage:   "address:port to listen on",
				},
			},
			Subcommands: Commands{
				&Command{
					Name:    "serve",
					Aliases: []string{"s"},
					Usage:   "Run server listener",
					Action: func(ctx *Context) error {
						conf := cfg()
						address := ctx.String("address")
						if address == "" {
							address = conf.Address
						}

						middleware := []http.Middleware{}
						middleware = append(
							middleware,
							http.Trace(conf.Trace),
							http.Recover(),
						)

						if conf.Session != nil && conf.Session.Enable {
							store, err := http.NewTokenStore(
								conf.Session.Store,
								http.NewTokenContainer(conf.Session.Container),
							)
							if err != nil {
								return err
							}
							middleware = append(
								middleware,
								http.Session(
									conf.Session,
									store,
									http.NewTokenValidator(conf.Session.Validator),
								),
							)
						}
						options := []http.Option{
							http.WithAddress(address),
							http.WithHandler(http.Compose(router, middleware...)),
							http.WithMetricsHandler(metrics.Default, router),
						}
						return http.New(conf, options...).ListenAndServe()
					},
				},
			},
		})
	}
}

func New(options ...Option) *Cli {
	c := &Cli{
		App: &App{},
	}

	for _, option := range options {
		option(c)
	}

	return c
}
