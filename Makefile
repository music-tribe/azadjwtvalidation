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

run_tests: tools
	go test ./... -v

run_tests_short: tools
	go test ./... -v -short

ci_test: tools
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...

ci_staticcheck: tools
	staticcheck -checks "all, -ST1000, -ST1001, -ST1003, -ST1016, -ST1020, -ST1021, -ST1022" ./...

race: tools
	CGO_ENABLED=1 go test -v -race $(_GO_TEST_SHORT) ./...

go_vuln:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...