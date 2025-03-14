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
	Regex        Regexp `yaml:"regex,omitempty"`
	Redirect     string `yaml:"redirect,omitempty"`
	StatusCode   int    `yaml:"status,omitempty"`
	Query        bool   `yaml:"query,omitempty"`
	Fragment     bool   `yaml:"fragment,omitempty"`
	IncludeQuery bool   `yaml:"include_query,omitempty"`
}

type ConfigFile struct {
	Base      string      `yaml:"baseurl,omitempty"`
	Prefix    string      `yaml:"prefix,omitempty"`
	AddPrefix string      `yaml:"addprefix,omitempty"`
	Config    []Configlet `yaml:"redirect,omitempty"`
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
	redirect, code := hdl.redirect(r.URL)
	if redirect != "" {
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

func (hdl *Handler) fixurl(u *url.URL, v *Configlet, redirect_to string) string {
	res := redirect_to
	var err error
	if hdl.configdata.Base != "" {
		res, err = url.JoinPath(hdl.configdata.Base, res)
		if err != nil {
			slog.Error("joinpath", "base", hdl.configdata.Base, "target", res, "error", err)
			return ""
		}
	}
	if v.Query && u.RawQuery != "" {
		res += "?" + u.RawQuery
	}
	if v.Fragment && u.RawFragment != "" {
		res += "#" + u.RawFragment
	}
	if hdl.configdata.AddPrefix != "" {
		res = hdl.configdata.AddPrefix + res
	}
	return res
}

func (hdl *Handler) redirect(u *url.URL) (string, int) {
	path := u.Path
	if hdl.configdata.Prefix != "" {
		path = hdl.configdata.Prefix + path
	}
	for _, v := range hdl.configdata.Config {
		vpath := path
		if v.IncludeQuery && u.RawQuery != "" {
			vpath += "?" + u.RawQuery
		}
		slog.Debug("check", "path", vpath, "match", v.Regex.String())
		if v.Regex.MatchString(vpath) {
			var code int = http.StatusMovedPermanently
			if v.StatusCode != 0 {
				code = v.StatusCode
			}
			res1 := v.Regex.ReplaceAllString(vpath, v.Redirect)
			res2 := hdl.fixurl(u, &v, res1)
			if res2 == "" {
				// error?
				slog.Warn("cannot fix", "result", res1)
				continue
			}
			return res2, code
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
