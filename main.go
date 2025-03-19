package main

import (
	"log/slog"
	"os"

	"github.com/jessevdk/go-flags"
)

var globalOption struct {
	Verbose bool `short:"v" long:"verbose" description:"show verbose logs"`
	Quiet   bool `short:"q" long:"quiet" description:"suppress logs"`
	JsonLog bool `long:"json-log" description:"use json format for logging"`
}

func init_log(verbose, quiet, json_log bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	} else if quiet {
		level = slog.LevelWarn
	}
	if json_log {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	} else {
		slog.SetLogLoggerLevel(level)
	}
}

type SubCommand struct {
	Name  string
	Short string
	Long  string
	Data  interface{}
}

func realMain() int {
	var err error
	commands := []SubCommand{
		{Name: "webserver", Short: "boot webserver", Long: "boot zipweb", Data: &WebServer{}},
	}
	parser := flags.NewParser(&globalOption, flags.Default)
	for _, cmd := range commands {
		_, err = parser.AddCommand(cmd.Name, cmd.Short, cmd.Long, cmd.Data)
		if err != nil {
			slog.Error(cmd.Name, "error", err)
			return -1
		}
	}
	if _, err := parser.Parse(); err != nil {
		if _, ok := err.(*flags.Error); ok {
			return 0
		}
		slog.Error("error exit", "error", err)
		parser.WriteHelp(os.Stdout)
		return 1
	}
	return 0
}

func main() {
	os.Exit(realMain())
}
