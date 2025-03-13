package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"

	"gopkg.in/yaml.v3"
)

type Regexp struct {
	*regexp.Regexp
}

type Configlet struct {
	Regex      Regexp `yaml:"regex,omitempty"`
	Redirect   string `yaml:"redirect,omitempty"`
	StatusCode int    `yaml:"status,omitempty"`
}

type ConfigFile struct {
	Base   string      `yaml:"baseurl"`
	Config []Configlet `yaml:"redirect"`
}

type Handler struct {
	configdata ConfigFile
	configfile string
	server     *http.Server
	rwlock     *sync.RWMutex
}

func (re *Regexp) UnmarshalText(input []byte) error {
	regex, err := regexp.Compile(string(input))
	if err != nil {
		return err
	}
	re.Regexp = regex
	return nil
}

func (re *Regexp) MarshalText() ([]byte, error) {
	if re.Regexp != nil {
		return []byte(re.Regexp.String()), nil
	}
	return nil, nil
}

func (hdl *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdl.rwlock.RLock()
	defer hdl.rwlock.RUnlock()
	slog.Info("request", "url", r.URL)
	redirect, code := hdl.redirect(r.URL.Path)
	if redirect != "" {
		if r.URL.RawQuery != "" {
			redirect += "?" + r.URL.RawQuery
		}
		if r.URL.Fragment != "" {
			redirect += "#" + r.URL.Fragment
		}
		w.Header().Set("Location", redirect)
	}
	slog.Info("response", "status", code, "location", redirect)
	w.WriteHeader(code)
}

func (hdl *Handler) Reload() error {
	rdata, err := hdl.load(hdl.configfile)
	if err != nil {
		slog.Error("load error", "error", err)
		return err
	}
	hdl.rwlock.Lock()
	defer hdl.rwlock.Unlock()
	hdl.configdata = *rdata
	return nil
}

func (hdl *Handler) load(fname string) (*ConfigFile, error) {
	fi, err := os.Open(fname)
	if err != nil {
		slog.Error("cannot open", "fname", fname, "error", err)
		return nil, err
	}
	defer fi.Close()
	dec := yaml.NewDecoder(fi)
	var config ConfigFile
	err = dec.Decode(&config)
	if err != nil {
		slog.Error("cannot decode", "fname", fname, "error", err)
		return nil, err
	}
	slog.Info("loaded", "file", fname, "config", config)
	return &config, nil
}

func (hdl *Handler) Shutdown() error {
	ctx := context.TODO()
	return hdl.server.Shutdown(ctx)
}

func (hdl *Handler) redirect(path string) (string, int) {
	var err error
	for _, v := range hdl.configdata.Config {
		if v.Regex.MatchString(path) {
			var code int = 301
			if v.StatusCode != 0 {
				code = v.StatusCode
			}
			res := v.Regex.ReplaceAllString(path, v.Redirect)
			if hdl.configdata.Base != "" {
				res, err = url.JoinPath(hdl.configdata.Base, res)
				if err != nil {
					slog.Error("joinpath", "base", hdl.configdata.Base, "target", res, "error", err)
					return "", http.StatusInternalServerError
				}
			}
			return res, code
		}
	}
	return "", http.StatusNotFound
}

func main() {
	var (
		config = flag.String("config", "", "config file")
		listen = flag.String("listen", ":8000", "listen address")
	)
	flag.Parse()
	slog.Info("hello world")
	server := http.Server{
		Addr:     *listen,
		Handler:  nil,
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelInfo),
	}
	handler := Handler{
		configfile: *config,
		server:     &server,
		rwlock:     &sync.RWMutex{},
	}
	http.Handle("/", &handler)
	if err := handler.Reload(); err != nil {
		slog.Error("loading config", "error", err)
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		var err error
		for {
			sig := <-sigs
			slog.Info("caught signal", "signal", sig)
			switch sig {
			case syscall.SIGHUP:
				if err = handler.Reload(); err != nil {
					slog.Error("reload failed", "error", err)
					return
				}
			case syscall.SIGINT, syscall.SIGTERM:
				if err = handler.Shutdown(); err != nil {
					slog.Error("terminate failed", "error", err)
				}
				return
			}
		}
	}()
	slog.Info("starting server", "listen", server.Addr, "pid", os.Getpid())
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		slog.Error("listen error", "error", err)
		return
	}
	slog.Info("server closed", "msg", err)
}
