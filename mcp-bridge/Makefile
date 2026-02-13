# GhidraMCP Bridge - Cross-compilation Makefile
#
# Targets:
#   make all          - Build for all platforms
#   make linux        - Build for Linux x86_64
#   make windows      - Build for Windows x86_64
#   make mac_intel    - Build for macOS x86_64
#   make mac_arm      - Build for macOS ARM64
#   make clean        - Remove all build artifacts
#   make tidy         - Run go mod tidy

MODULE   := github.com/ghidramcp/mcp-bridge
BINARY   := mcp_bridge
VERSION  := 1.0.0
LDFLAGS  := -s -w -X main.Version=$(VERSION)

DIST     := dist/os

.PHONY: all linux windows mac_intel mac_arm clean tidy

all: linux windows mac_intel mac_arm

tidy:
	go mod tidy

linux:
	@echo "Building for Linux x86_64..."
	@mkdir -p $(DIST)/linux_x86_64
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/linux_x86_64/$(BINARY) .

windows:
	@echo "Building for Windows x86_64..."
	@mkdir -p $(DIST)/win_x86_64
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/win_x86_64/$(BINARY).exe .

mac_intel:
	@echo "Building for macOS x86_64..."
	@mkdir -p $(DIST)/mac_x86_64
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/mac_x86_64/$(BINARY) .

mac_arm:
	@echo "Building for macOS ARM64..."
	@mkdir -p $(DIST)/mac_aarch64
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/mac_aarch64/$(BINARY) .

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(DIST)
	rm -rf dist
