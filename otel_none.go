//go:build !otel

package main

import (
	"errors"
	"log/slog"
	"net/http"
)

func init_otel(handler http.Handler, name string) (func(), http.Handler, error) {
	slog.Info("this binary does not supports opentelemetry")
	return nil, nil, errors.ErrUnsupported
}
