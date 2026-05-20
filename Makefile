BINARY  := satpam-agent
CMD     := ./cmd/satpam-agent

OS := $(shell go env GOOS)
ifeq ($(OS),windows)
  BIN := $(BINARY).exe
else
  BIN := $(BINARY)
endif

.PHONY: build test clean

build:
	go build -o $(BIN) $(CMD)
	@echo "Built: $(BIN) ($(OS)/$(shell go env GOARCH))"

test:
	go test ./...

clean:
	rm -f $(BINARY) $(BINARY).exe
