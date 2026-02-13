// GhidraMCP Bridge -- a Go binary that sits between Claude Desktop (stdio/MCP)
// and the GhidraMCP Java plugin (TCP, length-prefixed JSON-RPC).
//
// Usage:
//
//	mcp_bridge --host localhost --port 8765 [--api-key KEY]
//	GHIDRA_API_KEY=secret mcp_bridge --host localhost --port 8765
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ghidramcp/mcp-bridge/internal/ghidra"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ghidraMultiClient manages connections to one or more Ghidra instances.
// It is initialised in main() before the MCP server starts.
var ghidraMultiClient *ghidra.MultiClient

// ---------------------------------------------------------------------------
// Helpers: forward tool calls to Ghidra and return raw JSON as text.
// ---------------------------------------------------------------------------

// forwardWithTargetPort extracts the optional "target_port" parameter from
// the MCP request and routes to the corresponding Ghidra instance.
func forwardWithTargetPort(req mcp.CallToolRequest, method string, params map[string]interface{}) (*mcp.CallToolResult, error) {
	port := req.GetInt("target_port", 0)
	result, err := ghidraMultiClient.Request(method, params, port)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(result)), nil
}

// optionalPagination adds offset/limit to params if present in the request.
// Uses the type-safe GetInt accessor from mcp-go v0.29+.
// A sentinel value of -1 means the parameter was not supplied.
func optionalPagination(req mcp.CallToolRequest, params map[string]interface{}) {
	if v := req.GetInt("offset", -1); v >= 0 {
		params["offset"] = v
	}
	if v := req.GetInt("limit", -1); v >= 0 {
		params["limit"] = v
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	host := flag.String("host", "localhost", "GhidraMCP server hostname")
	port := flag.Int("port", 8765, "GhidraMCP server TCP port")
	apiKey := flag.String("api-key", "", "API key for Ghidra authentication (prefer GHIDRA_API_KEY env var)")
	flag.Parse()

	// Redirect log output to stderr so it does not corrupt the stdio MCP
	// transport on stdout.
	log.SetOutput(os.Stderr)

	// SEC-1: Prefer the GHIDRA_API_KEY environment variable over the CLI
	// flag to avoid leaking the key in the process table (visible via ps).
	resolvedKey := *apiKey
	if envKey := os.Getenv("GHIDRA_API_KEY"); envKey != "" {
		resolvedKey = envKey
		if *apiKey != "" {
			log.Println("Warning: both --api-key flag and GHIDRA_API_KEY env var set; using env var")
		}
	}

	// Handle SIGINT/SIGTERM for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		if ghidraMultiClient != nil {
			ghidraMultiClient.CloseAll()
		}
		os.Exit(0)
	}()

	var err error
	ghidraMultiClient, err = ghidra.NewMultiClientWithRetry(*host, *port, resolvedKey, ghidra.DefaultRetryConfig())
	if err != nil {
		log.Fatalf("Failed to connect to Ghidra: %v", err)
	}
	defer ghidraMultiClient.CloseAll()

	log.Printf("Connected to Ghidra at %s:%d", *host, *port)

	s := server.NewMCPServer("GhidraMCP", "1.0.0")

	registerAllTools(s)

	log.Println("MCP server starting on stdio...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}
