package tracing

import (
	"io"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.uber.org/zap"
	"gopkg.in/natefinch/lumberjack.v2"
)

// newExporter returns a console trace exporter.
func newExporter(w io.Writer) (trace.SpanExporter, error) {
	return stdouttrace.New(
		stdouttrace.WithWriter(w),
		// Use human-readable output.
		stdouttrace.WithPrettyPrint(),
	)
}

// newResource returns a resource describing this application.
func newResource(version string) (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("github.com/uselagoon/ssh-portal"),
			semconv.ServiceVersionKey.String(version),
			attribute.String("example", "example value"),
		),
	)
}

func newTraceWriter() *lumberjack.Logger {
	return &lumberjack.Logger{
		MaxBackups: 2,
	}
}

// NewTracerProvider initialises and returns a new tracer provider which by
// default logs to /tmp. It implements its own trace log rotation.
// w.Close() and tp.Shutdown() should be deferred by the caller.
func NewTracerProvider(log *zap.Logger, version string) (*lumberjack.Logger, *trace.TracerProvider, error) {
	w := newTraceWriter()
	exp, err := newExporter(w)
	if err != nil {
		return nil, nil, err
	}
	res, err := newResource(version)
	if err != nil {
		return nil, nil, err
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return w, tp, nil
}
