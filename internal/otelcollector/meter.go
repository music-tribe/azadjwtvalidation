package otelcollector

import (
	"context"

	"go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// FIXME: Issues with grpc package & yaegi. Panic on init. Possibly related to Golang version
// // Initialise a MeterProvider that exports metrics to an OpenTelemetry Collector via gRPC
// func InitGrpcMeterProvider(ctx context.Context, res *resource.Resource, conn *grpc.ClientConn) (*sdkmetric.MeterProvider, error) {
// 	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create metrics exporter: %w", err)
// 	}

// 	meterProvider := sdkmetric.NewMeterProvider(
// 		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
// 		sdkmetric.WithResource(res),
// 	)

// 	return meterProvider, nil
// }

func InitPrometheusMeterProvider(ctx context.Context, res *resource.Resource) (*sdkmetric.MeterProvider, error) {
	// The exporter embeds a default OpenTelemetry Reader and
	// implements prometheus.Collector, allowing it to be used as
	// both a Reader and Collector.
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}

	// Register the exporter with the global meter provider
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithResource(res),
	)

	return meterProvider, nil
}
