package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

func prepare_test(t *testing.T, td string, config string) (*http.Client, *httptest.Server, error) {
	t.Helper()
	tmpname := filepath.Join(td, "test.yaml")
	fi, err := os.Create(tmpname)
	if err != nil {
		t.Error("tmpfile create", err)
		return nil, nil, err
	}
	defer fi.Close()
	if written, err := io.WriteString(fi, `
redirect:
- regex: /hello/([a-z]*)/
  redirect: /world/$1/index.html
- regex: /foo/bar/baz
  redirect: /bar/baz/foo
`); err != nil {
		t.Error("tmpfile write", err, written)
		return nil, nil, err
	}
	if err := fi.Sync(); err != nil {
		t.Error("tmpfile sync", err)
	}
	hdl := Handler{
		configfile: tmpname,
		rwlock:     &sync.RWMutex{},
	}
	if err := hdl.Reload(); err != nil {
		t.Error("reload", err)
	}
	ts := httptest.NewServer(&hdl)
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, ts, nil
}

func TestRedir(t *testing.T) {
	c, ts, err := prepare_test(t, t.TempDir(), `
redirect:
- regex: /hello/([a-z]*)/
  redirect: /world/$1/index.html
- regex: /foo/bar/baz
  redirect: /bar/baz/foo
`)
	if err != nil {
		t.Error("prep failed", err)
		return
	}
	defer ts.Close()
	u, err := url.JoinPath(ts.URL, "/hello/abcde/")
	if err != nil {
		t.Error("joinpath", err)
	}
	t.Log("url", u)
	res, err := c.Get(u)
	if err != nil {
		t.Error("get", err)
	}
	if res.StatusCode != http.StatusMovedPermanently {
		t.Error("status code", res.StatusCode)
	}
	if res.Header.Get("Location") != "/world/abcde/index.html" {
		t.Error("redirect to", res.Header.Get("Location"))
	}
}

func TestSave(t *testing.T) {
	td := t.TempDir()
	_, ts, err := prepare_test(t, td, `
redirect:
- regex: /hello/([a-z]*)/
  redirect: /world/$1/index.html
- regex: /foo/bar/baz
  redirect: /bar/baz/foo
`)
	if err != nil {
		t.Error("prep failed", err)
		return
	}
	defer ts.Close()
	if err := ts.Config.Handler.(*Handler).Save(); err != nil {
		t.Error("save", err)
	}
	tmpname := filepath.Join(td, "test.yaml")
	if _, err := os.Stat(tmpname); err != nil {
		t.Error("not saved", err)
	}
	if _, err := os.Stat(tmpname + ".bak"); err != nil {
		t.Error("no backup", err)
	}
	saved, err := os.Open(tmpname)
	if err != nil {
		t.Error("cannot open", err)
		return
	}
	val := make(map[string]interface{}, 0)
	dec := yaml.NewDecoder(saved)
	if err := dec.Decode(val); err != nil {
		t.Error("decode", err)
	}
	t.Log("decoded", val)
	v, ok := val["redirect"]
	if !ok {
		t.Error("no redirect", val)
	}
	vv := v.([]interface{})
	if vv == nil {
		t.Error("not list", v)
	}
	if len(vv) != 2 {
		t.Error("redirct content", v)
	}
	v1 := vv[0].(map[string]interface{})
	if v1 == nil {
		t.Error("redirect content[0]", vv[0])
	} else {
		if v1["regex"] != `/hello/([a-z]*)/` {
			t.Error("redirect regex[0]", v1)
		}
		if v1["redirect"] != `/world/$1/index.html` {
			t.Error("redirect redirect[0]", v1)
		}
	}
}
