package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/dlclark/regexp2"
	glob "github.com/pachyderm/ohmyglob"
	"gopkg.in/yaml.v3"
)

type Regexp struct {
	*regexp.Regexp
}

type Regexp2 struct {
	*regexp2.Regexp
}

type Configlet struct {
	Regex        *Regexp  `yaml:"regex,omitempty"`
	Regex2       *Regexp2 `yaml:"regex2,omitempty"`
	Prefix       string   `yaml:"prefix,omitempty"`
	Suffix       string   `yaml:"suffix,omitempty"`
	Exact        string   `yaml:"exact,omitempty"`
	Glob         string   `yaml:"glob,omitempty"`
	Redirect     string   `yaml:"redirect,omitempty"`
	StatusCode   int      `yaml:"status,omitempty"`
	Query        bool     `yaml:"query,omitempty"`
	Fragment     bool     `yaml:"fragment,omitempty"`
	IncludeQuery bool     `yaml:"include_query,omitempty"`
}

type ConfigFile struct {
	Base      string      `yaml:"baseurl,omitempty"`
	Prefix    string      `yaml:"prefix,omitempty"`
	AddPrefix string      `yaml:"addprefix,omitempty"`
	Config    []Configlet `yaml:"redirect,omitempty"`
}

func (c *Configlet) replace(path, query string) (string, error) {
	vpath := path
	if c.IncludeQuery && query != "" {
		vpath += "?" + query
	}
	if c.Exact != "" && c.Exact == vpath {
		slog.Debug("exact match", "pattern", c.Exact, "vpath", vpath, "to", c.Redirect)
		return c.Redirect, nil
	}
	if c.Prefix != "" && strings.HasPrefix(vpath, c.Prefix) {
		slog.Debug("prefix match", "pattern", c.Prefix, "vpath", vpath, "to", c.Redirect)
		return c.Redirect + vpath[len(c.Prefix):], nil
	}
	if c.Suffix != "" && strings.HasSuffix(vpath, c.Prefix) {
		slog.Debug("suffix match", "pattern", c.Suffix, "vpath", vpath, "to", c.Redirect)
		return vpath[:len(c.Suffix)] + c.Redirect, nil
	}
	if c.Regex != nil && c.Regex.MatchString(vpath) {
		slog.Info("regex match", "pattern", c.Regex, "vpath", vpath, "to", c.Redirect)
		return c.Regex.ReplaceAllString(vpath, c.Redirect), nil
	}
	if c.Regex2 != nil {
		if ok, err := c.Regex2.MatchString(vpath); err != nil && ok {
			slog.Debug("regex2 match", "pattern", c.Regex2, "vpath", vpath, "to", c.Redirect)
			return c.Regex2.Replace(vpath, c.Redirect, -1, -1)
		}
	}
	if c.Glob != "" {
		g, err := glob.Compile(c.Glob)
		if err != nil {
			slog.Info("glob error", "pattern", c.Glob, "error", err)
			return "", err
		}
		if g.Match(vpath) {
			slog.Debug("glob match", "pattern", c.Glob, "vpath", vpath, "to", c.Redirect)
			return g.Replace(vpath, c.Redirect), nil
		}
	}
	return "", fmt.Errorf("not match")
}

type Handler struct {
	configdata ConfigFile
	configfile string
	server     *http.Server
	rwlock     *sync.RWMutex
}

func (re *Regexp) UnmarshalYAML(input *yaml.Node) error {
	regex, err := regexp.Compile(input.Value)
	if err != nil {
		return err
	}
	re.Regexp = regex
	return nil
}

func (re *Regexp2) UnmarshalYAML(input *yaml.Node) error {
	regex, err := regexp2.Compile(input.Value, 0)
	if err != nil {
		return err
	}
	re.Regexp = regex
	return nil
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
	rdata, err := hdl.load_yaml(hdl.configfile)
	if err != nil {
		slog.Error("load error", "error", err)
		return err
	}
	hdl.rwlock.Lock()
	defer hdl.rwlock.Unlock()
	hdl.configdata = *rdata
	return nil
}

func (hdl *Handler) load_yaml(fname string) (*ConfigFile, error) {
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

func (hdl *Handler) Save() error {
	return hdl.dump_yaml(hdl.configfile)
}

func (hdl *Handler) dump_yaml(fname string) error {
	bakname := fname + ".bak"
	err := os.Rename(fname, bakname)
	if err != nil {
		slog.Debug("cannot rename", "fname", fname, "bakname", bakname, "error", err)
	}
	fo, err := os.Create(fname)
	if err != nil {
		slog.Error("cannot open(create)", "fname", fname, "error", err)
		return err
	}
	defer fo.Close()
	enc := yaml.NewEncoder(fo)
	enc.SetIndent(2)
	err = enc.Encode(hdl.configdata)
	if err != nil {
		slog.Error("cannot encode", "fname", fname, "error", err)
		return err
	}
	slog.Info("saved", "file", fname, "config", hdl.configdata)
	return nil
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
	for idx, v := range hdl.configdata.Config {
		var code int = http.StatusMovedPermanently
		slog.Debug("check", "rule-id", idx, "path", path, "rule", v)
		res1, err := v.replace(path, u.RawQuery)
		if err != nil {
			if err.Error() != "not match" {
				slog.Warn("replace error", "error", err)
			}
			continue
		}
		if res1 != "" {
			if v.StatusCode != 0 {
				code = v.StatusCode
			}
			res2 := hdl.fixurl(u, &v, res1)
			slog.Debug("replaced", "rule-id", idx, "orig", u, "changed", res1, "fixed", res2)
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

func (hdl *Handler) ServeSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	go func() {
		var err error
		for {
			sig := <-sigs
			slog.Info("caught signal", "signal", sig)
			switch sig {
			case syscall.SIGHUP:
				if err = hdl.Reload(); err != nil {
					slog.Error("reload failed", "error", err)
					return
				}
			case syscall.SIGUSR1:
				if err = hdl.Save(); err != nil {
					slog.Error("save failed", "error", err)
					return
				}
			case syscall.SIGINT, syscall.SIGTERM:
				if err = hdl.Shutdown(); err != nil {
					slog.Error("terminate failed", "error", err)
				}
				return
			}
		}
	}()
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

func do_listen(listen string) (net.Listener, error) {
	protos := strings.SplitN(listen, ":", 2)
	switch protos[0] {
	case "unix", "tcp", "tcp4", "tcp6":
		return net.Listen(protos[0], protos[1])
	}
	return net.Listen("tcp", listen)
}

func main() {
	var (
		config   = flag.String("config", "", "config file")
		listen   = flag.String("listen", ":8000", "listen address")
		verbose  = flag.Bool("verbose", false, "verbose output")
		quiet    = flag.Bool("quiet", false, "quiet output")
		json_log = flag.Bool("json-log", false, "json logger")
	)
	flag.Parse()
	init_log(*verbose, *quiet, *json_log)
	server := http.Server{
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
	handler.ServeSignal()

	listener, err := do_listen(*listen)
	if err != nil {
		slog.Error("listen error", "error", err)
		return
	}
	slog.Info("server starting", "listen", listener.Addr(), "pid", os.Getpid())
	err = server.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		slog.Error("listen error", "error", err)
		return
	}
	slog.Info("server closed", "msg", err)
}
