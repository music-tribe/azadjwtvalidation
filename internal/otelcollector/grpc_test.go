package otelcollector

// import (
// 	"context"
// 	"testing"

// 	"go.opentelemetry.io/otel/attribute"
// 	"go.opentelemetry.io/otel/sdk/resource"
// )

// func TestInitGrpcConn(t *testing.T) {
// 	ctx := context.Background()
// 	serviceName := attribute.Key("azadjwtvalidation")
// 	cfg := GrpcConfig{
// 		Target: "localhost:4317",
// 	}
// 	conn, err := InitGrpcConn(ctx, cfg)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	res, err := resource.New(ctx,
// 		resource.WithAttributes(
// 			attribute.KeyValue{Key: serviceName},
// 		),
// 	)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	_, err = InitMeterProvider(ctx, res, conn)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }
