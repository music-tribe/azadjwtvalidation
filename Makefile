ifndef $(GOPATH)
    GOPATH=$(shell go env GOPATH)
    export GOPATH
endif

# Alias for tools
tools: .tools
.PHONY: tools

.tools:
	curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b $(GOPATH)/bin v2.22.4
	go install honnef.co/go/tools/cmd/staticcheck@v0.6.1
	touch .tools

clean_tools:
	rm -f .tools
.PHONY: clean_tools

mocks:
	go install go.uber.org/mock/mockgen@v0.5.2
	go generate ./...

clean_mocks:
	find . -name "mock_*" -type f  -exec rm -r {} +

run_tests: tools mocks
	go test ./... -v

run_tests_short: tools mocks
	go test ./... -v -short

ci_test: tools mocks
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...

ci_staticcheck: tools mocks
	staticcheck -checks "all, -ST1000, -ST1001, -ST1003, -ST1016, -ST1020, -ST1021, -ST1022" ./...

race: tools mocks
	CGO_ENABLED=1 go test -v -race $(_GO_TEST_SHORT) ./...

go_vuln:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...