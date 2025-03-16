//go:build otel

package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

func init_otel(handler http.Handler, name string) (func(), http.Handler, error) {
	slog.Info("initialize opentelemetry")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		slog.Error("initialize opentelemetry failed", "error", err)
		return nil, nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(name),
		)),
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return func() {
		stop()
		if err := tp.Shutdown(ctx); err != nil {
			slog.Error("trace provider shutdown error", "error", err)
		}
	}, otelhttp.NewHandler(handler, name), nil
}
