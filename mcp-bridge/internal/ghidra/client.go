// Package ghidra provides a TCP client for communicating with the GhidraMCP
// Java plugin using length-prefixed binary framing and JSON-RPC messages.
package ghidra

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ValidPort returns true if the port is in the valid TCP range [1, 65535].
func ValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// Default timeout for individual read/write operations on the TCP connection.
const defaultIOTimeout = 60 * time.Second

// MaxMessageSize is the maximum allowed message size (50 MB), matching the
// Java side's limit to prevent OOM from malformed length prefixes.
const MaxMessageSize = 50 * 1024 * 1024

// ---------------------------------------------------------------------------
// GhidraClient — single TCP connection to one Ghidra instance
// ---------------------------------------------------------------------------

// GhidraClient manages a single TCP connection to the GhidraMCP Java plugin
// and serialises request/response pairs through a mutex.
type GhidraClient struct {
	conn   net.Conn
	mu     sync.Mutex
	nextID atomic.Int64
	host   string     // stored for reconnection
	port   int        // stored for reconnection
	apiKey string     // stored for reconnection
	closed atomic.Bool
}

// rpcRequest is the JSON-RPC request envelope sent to Ghidra.
type rpcRequest struct {
	ID     string                 `json:"id"`
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// rpcResponse is the JSON-RPC response envelope received from Ghidra.
type rpcResponse struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// authenticate sends an authentication request using the stored API key.
// The caller must hold c.mu (or the client must not be shared yet).
func (c *GhidraClient) authenticate() error {
	if c.apiKey == "" {
		return nil
	}
	result, err := c.requestInternal("authenticate", map[string]interface{}{
		"apiKey": c.apiKey,
	})
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	var ok bool
	if err := json.Unmarshal(result, &ok); err != nil || !ok {
		return fmt.Errorf("authentication rejected by Ghidra server")
	}
	return nil
}

// NewClient dials the GhidraMCP TCP server and optionally authenticates
// with the provided API key. If apiKey is empty, authentication is skipped.
func NewClient(host string, port int, apiKey string) (*GhidraClient, error) {
	if !ValidPort(port) {
		return nil, fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ghidra at %s: %w", addr, err)
	}

	c := &GhidraClient{
		conn:   conn,
		host:   host,
		port:   port,
		apiKey: apiKey,
	}

	if err := c.authenticate(); err != nil {
		conn.Close()
		return nil, err
	}

	return c, nil
}

// ---------------------------------------------------------------------------
// Retry configuration
// ---------------------------------------------------------------------------

// RetryConfig controls retry behavior for connection attempts.
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// DefaultRetryConfig returns sensible defaults: 10 retries, 1s initial, 30s max.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     10,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     30 * time.Second,
	}
}

// NewClientWithRetry attempts to connect to Ghidra with exponential backoff.
func NewClientWithRetry(host string, port int, apiKey string, cfg RetryConfig) (*GhidraClient, error) {
	var lastErr error
	backoff := cfg.InitialBackoff

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("Retry %d/%d: connecting to Ghidra at %s:%d (backoff %v)...",
				attempt, cfg.MaxRetries, host, port, backoff)
			time.Sleep(backoff)

			// Exponential backoff with cap
			backoff = time.Duration(float64(backoff) * 2)
			if backoff > cfg.MaxBackoff {
				backoff = cfg.MaxBackoff
			}
		}

		client, err := NewClient(host, port, apiKey)
		if err == nil {
			if attempt > 0 {
				log.Printf("Connected to Ghidra after %d retries", attempt)
			}
			return client, nil
		}
		lastErr = err
		log.Printf("Connection attempt %d failed: %v", attempt+1, lastErr)
	}

	return nil, fmt.Errorf("failed to connect after %d attempts: %w", cfg.MaxRetries+1, lastErr)
}

// ---------------------------------------------------------------------------
// Request / reconnect logic
// ---------------------------------------------------------------------------

// requestInternal performs the actual request I/O without locking.
// The caller must hold c.mu.
func (c *GhidraClient) requestInternal(method string, params map[string]interface{}) (json.RawMessage, error) {
	id := fmt.Sprintf("%d", c.nextID.Add(1))

	req := rpcRequest{
		ID:     id,
		Method: method,
		Params: params,
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Set write deadline to prevent indefinite blocking on a stalled connection.
	if err := c.conn.SetWriteDeadline(time.Now().Add(defaultIOTimeout)); err != nil {
		return nil, fmt.Errorf("set write deadline: %w", err)
	}

	// Write: 4-byte big-endian length + payload.
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := c.conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("write length prefix: %w", err)
	}
	if _, err := c.conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}

	// Set read deadline to prevent indefinite blocking if Ghidra hangs.
	if err := c.conn.SetReadDeadline(time.Now().Add(defaultIOTimeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	// Read: 4-byte big-endian length.
	if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen == 0 || respLen > MaxMessageSize {
		return nil, fmt.Errorf("invalid response length: %d", respLen)
	}

	// Read the exact response payload.
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(c.conn, respBuf); err != nil {
		return nil, fmt.Errorf("read response payload: %w", err)
	}

	// Clear deadlines after successful read/write cycle.
	c.conn.SetDeadline(time.Time{})

	var resp rpcResponse
	if err := json.Unmarshal(respBuf, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("ghidra error: %s", resp.Error)
	}

	return resp.Result, nil
}

// isNetworkError returns true if the error indicates a connection problem
// (as opposed to a Ghidra application-level error).
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "write length prefix") ||
		strings.Contains(errStr, "write payload") ||
		strings.Contains(errStr, "read response length") ||
		strings.Contains(errStr, "read response payload") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "set write deadline") ||
		strings.Contains(errStr, "set read deadline")
}

// reconnect attempts to re-establish the TCP connection to Ghidra.
// The caller must hold c.mu.
func (c *GhidraClient) reconnect() error {
	if c.closed.Load() {
		return fmt.Errorf("client has been closed")
	}

	// Close old connection
	if c.conn != nil {
		c.conn.Close()
	}

	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("reconnect failed: %w", err)
	}

	c.conn = conn

	if err := c.authenticate(); err != nil {
		conn.Close()
		return fmt.Errorf("reconnect: %w", err)
	}

	return nil
}

// Request sends a JSON-RPC method call to Ghidra and blocks until the
// response is received. On network errors, it attempts one automatic
// reconnection before returning the error. It is safe for concurrent use.
func (c *GhidraClient) Request(method string, params map[string]interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	result, err := c.requestInternal(method, params)
	if err != nil && isNetworkError(err) {
		log.Printf("Request failed with network error, attempting reconnect: %v", err)

		if reconnErr := c.reconnect(); reconnErr != nil {
			return nil, fmt.Errorf("request failed and reconnect also failed: original=%v, reconnect=%v", err, reconnErr)
		}

		log.Printf("Reconnected successfully, retrying request")
		return c.requestInternal(method, params)
	}

	return result, err
}

// Close shuts down the underlying TCP connection and prevents reconnection.
func (c *GhidraClient) Close() error {
	c.closed.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// MultiClient — manages connections to multiple Ghidra instances
// ---------------------------------------------------------------------------

// MultiClient manages connections to multiple Ghidra instances on different ports.
type MultiClient struct {
	defaultPort int
	host        string
	apiKey      string
	clients     map[int]*GhidraClient
	mu          sync.RWMutex
}

// NewMultiClient creates a MultiClient and connects to the default port.
func NewMultiClient(host string, defaultPort int, apiKey string) (*MultiClient, error) {
	mc := &MultiClient{
		defaultPort: defaultPort,
		host:        host,
		apiKey:      apiKey,
		clients:     make(map[int]*GhidraClient),
	}

	client, err := NewClient(host, defaultPort, apiKey)
	if err != nil {
		return nil, err
	}
	mc.clients[defaultPort] = client
	return mc, nil
}

// NewMultiClientWithRetry creates a MultiClient using retry for the initial connection.
func NewMultiClientWithRetry(host string, defaultPort int, apiKey string, cfg RetryConfig) (*MultiClient, error) {
	mc := &MultiClient{
		defaultPort: defaultPort,
		host:        host,
		apiKey:      apiKey,
		clients:     make(map[int]*GhidraClient),
	}

	client, err := NewClientWithRetry(host, defaultPort, apiKey, cfg)
	if err != nil {
		return nil, err
	}
	mc.clients[defaultPort] = client
	return mc, nil
}

// GetClient returns the client for the given port. If port is 0 or matches
// the default, returns the default client. Lazily connects to new ports.
func (mc *MultiClient) GetClient(port int) (*GhidraClient, error) {
	if port == 0 || port == mc.defaultPort {
		mc.mu.RLock()
		c := mc.clients[mc.defaultPort]
		mc.mu.RUnlock()
		return c, nil
	}

	if !ValidPort(port) {
		return nil, fmt.Errorf("invalid target port %d: must be between 1 and 65535", port)
	}

	mc.mu.RLock()
	if c, ok := mc.clients[port]; ok {
		mc.mu.RUnlock()
		return c, nil
	}
	mc.mu.RUnlock()

	// Lazy connect
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Double-check after acquiring write lock
	if c, ok := mc.clients[port]; ok {
		return c, nil
	}

	c, err := NewClient(mc.host, port, mc.apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ghidra on port %d: %w", port, err)
	}
	mc.clients[port] = c
	return c, nil
}

// Request sends a request to the Ghidra instance on the specified port (0 = default).
func (mc *MultiClient) Request(method string, params map[string]interface{}, port int) (json.RawMessage, error) {
	c, err := mc.GetClient(port)
	if err != nil {
		return nil, err
	}
	return c.Request(method, params)
}

// scanPingTimeout is the per-port timeout for ScanPorts probes.
const scanPingTimeout = 3 * time.Second

// maxScanConcurrency limits the number of parallel goroutines in ScanPorts
// to prevent resource exhaustion when scanning wide port ranges.
const maxScanConcurrency = 10

// ScanPorts probes ports in the given range for active Ghidra MCP servers.
// Probes run in parallel (up to maxScanConcurrency) with scanPingTimeout per port.
// Discovered connections are NOT cached — use GetClient to lazily establish
// a properly authenticated connection when the user actually targets a port.
func (mc *MultiClient) ScanPorts(startPort, endPort int) []map[string]interface{} {
	if startPort > endPort || !ValidPort(startPort) || !ValidPort(endPort) {
		return nil
	}

	var results []map[string]interface{}
	var resultsMu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxScanConcurrency)

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore slot

			addr := fmt.Sprintf("%s:%d", mc.host, p)
			conn, err := net.DialTimeout("tcp", addr, scanPingTimeout)
			if err != nil {
				return // port not open
			}

			// Use a short I/O deadline for the probe.
			conn.SetDeadline(time.Now().Add(scanPingTimeout))

			// Try a ping to confirm it's a Ghidra MCP server
			tempClient := &GhidraClient{
				conn: conn,
				host: mc.host,
				port: p,
			}
			result, err := tempClient.requestInternal("ping", nil)
			if err != nil {
				conn.Close()
				return
			}

			// Always close the probe connection — GetClient will create a
			// properly authenticated connection if the port is actually used.
			conn.Close()

			// Check for "pong" response
			var pong string
			if err := json.Unmarshal(result, &pong); err == nil && pong == "pong" {
				resultsMu.Lock()
				results = append(results, map[string]interface{}{
					"port":   p,
					"status": "active",
				})
				resultsMu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

// CloseAll closes all connections.
func (mc *MultiClient) CloseAll() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	for _, c := range mc.clients {
		c.Close()
	}
}
