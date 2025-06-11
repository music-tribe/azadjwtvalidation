package otelcollector

// import (
// 	"context"
// 	"fmt"

// 	"google.golang.org/grpc"
// )

// // https://github.com/open-telemetry/opentelemetry-go-contrib/blob/main/examples/otel-collector/main.go

// type GrpcConfig struct {
// 	// FIXME: validate this and set a default value: localhost:4317
// 	Target string
// }

// // Initialize a gRPC connection that can be used by both the tracer and meter providers.
// func InitGrpcConn(ctx context.Context, cfg GrpcConfig) (*grpc.ClientConn, error) {
// 	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))
// 	conn, err := grpc.NewClient(cfg.Target,
// 		// FIXME: TLS is recommended in production.
// 		grpc.WithTransportCredentials(insecure.NewCredentials()),
// 	)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create gRPC connection to collector: %w", err)
// 	}

// 	return conn, err
// }
