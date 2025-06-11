module github.com/music-tribe/azadjwtvalidation

// FIXME: can we use go 1.24 with yeaegi?
go 1.23

// https://github.com/traefik/traefik/issues/7459
// "failed to craete Yaegi intepreter: failed to import plugin code \"github.com/music-tribe/azadjwtvalidation\": 1:21: import \"github.com/music-tribe/azadjwtvalidation\" error: plugins-local/src/github.com/music-tribe/azadjwtvalidation/validatetoken.go:24:2: import \"github.com/music-tribe/azadjwtvalidation/internal/otelcollector\" error: plugins-local/src/github.com/music-tribe/azadjwtvalidation/internal/otelcollector/meter.go:6:2: import \"go.opentelemetry.io/otel/exporters/prometheus\" error: plugins-local/src/github.com/music-tribe/azadjwtvalidation/vendor/go.opentelemetry.io/otel/exporters/prometheus/config.go:9:2: import \"github.com/prometheus/client_golang/prometheus\" error: plugins-local/src/github.com/music-tribe/azadjwtvalidation/vendor/github.com/prometheus/client_golang/prometheus/counter.go:22:2: import \"github.com/prometheus/client_model/go\" error: plugins-local/src/github.com/music-tribe/azadjwtvalidation/vendor/github.com/prometheus/client_model/go/metrics.pb.go:23:2: import \"google.golang.org/protobuf/reflect/protoreflect\" error: plugins-local/src/github.com/music-tribe/azadjwtvalidation/vendor/google.golang.org/protobuf/reflect/protoreflect/value_unsafe_go120.go:10:2: import \"unsafe\" error: unable to find source related to: \"unsafe\""
// Run in unsafe mode: https://github.com/traefik/traefik/pull/11589/files
// Not released yet: https://github.com/traefik/traefik/milestone/27?closed=1


require (
	github.com/go-playground/validator/v10 v10.26.0
	github.com/golang-jwt/jwt/v4 v4.4.2
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/otel v1.34.0
	go.opentelemetry.io/otel/exporters/prometheus v0.56.0
	go.opentelemetry.io/otel/metric v1.34.0
	go.opentelemetry.io/otel/sdk v1.34.0
	go.opentelemetry.io/otel/sdk/metric v1.34.0
	go.uber.org/mock v0.5.2
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.8 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.20.5 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.61.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/trace v1.34.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/protobuf v1.36.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
