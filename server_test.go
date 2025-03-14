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
)

func TestRedir(t *testing.T) {
	td := t.TempDir()
	tmpname := filepath.Join(td, "test.yaml")
	fi, err := os.Create(tmpname)
	if err != nil {
		t.Error("tmpfile create", err)
		return
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
		return
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
	defer ts.Close()
	c := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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
