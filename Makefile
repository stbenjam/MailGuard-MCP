BINARY := mailguard-mcp
GO := go
GOFLAGS :=

.PHONY: all build test vet lint fmt clean

all: build

build:
	$(GO) build $(GOFLAGS) -o $(BINARY) .

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

lint: vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

fmt:
	$(GO) fmt ./...

clean:
	rm -f $(BINARY)

check: fmt vet test
