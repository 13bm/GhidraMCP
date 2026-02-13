package ghidra

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// startFakeServer opens a TCP listener on a random port and returns it.
// The caller is responsible for closing the listener.
func startFakeServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake server: %v", err)
	}
	return ln
}

// portOf extracts the port number from a net.Listener.
func portOf(ln net.Listener) int {
	return ln.Addr().(*net.TCPAddr).Port
}

// readFrame reads a length-prefixed message from conn and returns the payload.
func readFrame(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf)
	if n == 0 || n > MaxMessageSize {
		return nil, fmt.Errorf("bad length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// writeFrame writes a length-prefixed message to conn.
func writeFrame(conn net.Conn, payload []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// writeRawLength writes a raw 4-byte big-endian length prefix only (no payload).
func writeRawLength(conn net.Conn, length uint32) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, length)
	_, err := conn.Write(buf)
	return err
}

// --------------------------------------------------------------------------
// TestFramingRoundtrip
// --------------------------------------------------------------------------

func TestFramingRoundtrip(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	// Fake server: accept one connection, read a request, echo back a result.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		payload, err := readFrame(conn)
		if err != nil {
			t.Errorf("server: readFrame: %v", err)
			return
		}

		// Verify it's valid JSON-RPC with the expected method.
		var req rpcRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			t.Errorf("server: unmarshal request: %v", err)
			return
		}
		if req.Method != "testMethod" {
			t.Errorf("server: expected method testMethod, got %s", req.Method)
			return
		}

		// Send back a response with the same id and a result.
		resp := rpcResponse{
			ID:     req.ID,
			Result: json.RawMessage(`{"status":"ok"}`),
		}
		respBytes, _ := json.Marshal(resp)
		if err := writeFrame(conn, respBytes); err != nil {
			t.Errorf("server: writeFrame: %v", err)
		}
	}()

	// Client side: connect (no auth) and send a request.
	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	result, err := c.Request("testMethod", map[string]interface{}{"key": "value"})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if parsed["status"] != "ok" {
		t.Errorf("expected status=ok, got %s", parsed["status"])
	}

	<-serverDone
}

// --------------------------------------------------------------------------
// TestMaxMessageSizeRejection
// --------------------------------------------------------------------------

func TestMaxMessageSizeRejection(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the client's request (we don't care about its contents).
		if _, err := readFrame(conn); err != nil {
			return
		}

		// Send a response with a length prefix > MaxMessageSize.
		if err := writeRawLength(conn, MaxMessageSize+1); err != nil {
			return
		}
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	_, err = c.Request("testMethod", nil)
	if err == nil {
		t.Fatal("expected error for oversized message, got nil")
	}
	t.Logf("correctly rejected oversized message: %v", err)
}

// --------------------------------------------------------------------------
// TestZeroLengthResponse
// --------------------------------------------------------------------------

func TestZeroLengthResponse(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		if _, err := readFrame(conn); err != nil {
			return
		}

		// Send a response with zero length.
		if err := writeRawLength(conn, 0); err != nil {
			return
		}
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	_, err = c.Request("testMethod", nil)
	if err == nil {
		t.Fatal("expected error for zero-length response, got nil")
	}
	t.Logf("correctly rejected zero-length response: %v", err)
}

// --------------------------------------------------------------------------
// TestAuthenticationSuccess
// --------------------------------------------------------------------------

func TestAuthenticationSuccess(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the auth request.
		payload, err := readFrame(conn)
		if err != nil {
			return
		}

		var req rpcRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return
		}

		if req.Method != "authenticate" {
			t.Errorf("expected method authenticate, got %s", req.Method)
			return
		}

		// Verify the apiKey parameter was forwarded.
		if req.Params["apiKey"] != "secret123" {
			t.Errorf("expected apiKey=secret123, got %v", req.Params["apiKey"])
		}

		// Send back success.
		resp := rpcResponse{
			ID:     req.ID,
			Result: json.RawMessage(`true`),
		}
		respBytes, _ := json.Marshal(resp)
		writeFrame(conn, respBytes)
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "secret123")
	if err != nil {
		t.Fatalf("NewClient with auth: %v", err)
	}
	defer c.Close()
}

// --------------------------------------------------------------------------
// TestAuthenticationFailure
// --------------------------------------------------------------------------

func TestAuthenticationFailure(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		payload, err := readFrame(conn)
		if err != nil {
			return
		}

		var req rpcRequest
		json.Unmarshal(payload, &req)

		// Send back an error (auth rejected).
		resp := rpcResponse{
			ID:    req.ID,
			Error: "bad key",
		}
		respBytes, _ := json.Marshal(resp)
		writeFrame(conn, respBytes)
	}()

	_, err := NewClient("127.0.0.1", portOf(ln), "wrongkey")
	if err == nil {
		t.Fatal("expected auth failure error, got nil")
	}
	t.Logf("correctly rejected bad auth: %v", err)
}

// --------------------------------------------------------------------------
// TestAuthenticationRejectedByFalseResult
// --------------------------------------------------------------------------

func TestAuthenticationRejectedByFalseResult(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		payload, err := readFrame(conn)
		if err != nil {
			return
		}

		var req rpcRequest
		json.Unmarshal(payload, &req)

		// The server returns boolean false (authentication rejected).
		resp := rpcResponse{
			ID:     req.ID,
			Result: json.RawMessage(`false`),
		}
		respBytes, _ := json.Marshal(resp)
		writeFrame(conn, respBytes)
	}()

	_, err := NewClient("127.0.0.1", portOf(ln), "wrongkey")
	if err == nil {
		t.Fatal("expected auth rejection for false result, got nil")
	}
	t.Logf("correctly rejected false auth result: %v", err)
}

// --------------------------------------------------------------------------
// TestConnectionRefused
// --------------------------------------------------------------------------

func TestConnectionRefused(t *testing.T) {
	// Pick a port that nothing is listening on.  Binding then immediately
	// closing guarantees the port was free.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(ln)
	ln.Close()

	_, err = NewClient("127.0.0.1", port, "")
	if err == nil {
		t.Fatal("expected connection-refused error, got nil")
	}
	t.Logf("correctly refused connection: %v", err)
}

// --------------------------------------------------------------------------
// TestConcurrentRequests
// --------------------------------------------------------------------------

func TestConcurrentRequests(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	const numRequests = 20

	// Fake server: accept one connection, handle numRequests requests
	// sequentially (the client's mutex serialises them).
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for i := 0; i < numRequests; i++ {
			payload, err := readFrame(conn)
			if err != nil {
				t.Errorf("server: readFrame %d: %v", i, err)
				return
			}
			var req rpcRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				t.Errorf("server: unmarshal %d: %v", i, err)
				return
			}

			// Echo the request's id and method back in the result.
			result := fmt.Sprintf(`{"echo_id":"%s","echo_method":"%s"}`, req.ID, req.Method)
			resp := rpcResponse{
				ID:     req.ID,
				Result: json.RawMessage(result),
			}
			respBytes, _ := json.Marshal(resp)
			if err := writeFrame(conn, respBytes); err != nil {
				t.Errorf("server: writeFrame %d: %v", i, err)
				return
			}
		}
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	errs := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			method := fmt.Sprintf("method_%d", idx)
			result, err := c.Request(method, nil)
			if err != nil {
				errs <- fmt.Errorf("request %d: %v", idx, err)
				return
			}

			var parsed map[string]string
			if err := json.Unmarshal(result, &parsed); err != nil {
				errs <- fmt.Errorf("unmarshal %d: %v", idx, err)
				return
			}
			if parsed["echo_method"] != method {
				errs <- fmt.Errorf("request %d: expected echo_method=%s, got %s",
					idx, method, parsed["echo_method"])
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// --------------------------------------------------------------------------
// TestRPCErrorResponse
// --------------------------------------------------------------------------

func TestRPCErrorResponse(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		payload, err := readFrame(conn)
		if err != nil {
			return
		}

		var req rpcRequest
		json.Unmarshal(payload, &req)

		// Server returns a JSON-RPC error.
		resp := rpcResponse{
			ID:    req.ID,
			Error: "something went wrong",
		}
		respBytes, _ := json.Marshal(resp)
		writeFrame(conn, respBytes)
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	_, err = c.Request("badCall", nil)
	if err == nil {
		t.Fatal("expected error from RPC error response, got nil")
	}
	expected := "ghidra error: something went wrong"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

// --------------------------------------------------------------------------
// TestCloseNilConn
// --------------------------------------------------------------------------

func TestCloseNilConn(t *testing.T) {
	c := &GhidraClient{conn: nil}
	if err := c.Close(); err != nil {
		t.Errorf("Close with nil conn should return nil, got %v", err)
	}
}

// --------------------------------------------------------------------------
// TestMalformedJSON
// --------------------------------------------------------------------------

func TestMalformedJSONResponse(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		if _, err := readFrame(conn); err != nil {
			return
		}

		// Send syntactically invalid JSON as the response body.
		writeFrame(conn, []byte(`{not valid json`))
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	_, err = c.Request("testMethod", nil)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	t.Logf("correctly rejected malformed JSON: %v", err)
}

// --------------------------------------------------------------------------
// TestConnectionClosedMidRead
// --------------------------------------------------------------------------

func TestConnectionClosedMidRead(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}

		// Read the request, then close without sending a response.
		readFrame(conn)
		conn.Close()
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	_, err = c.Request("testMethod", nil)
	if err == nil {
		t.Fatal("expected error when connection closed mid-read, got nil")
	}
	t.Logf("correctly detected closed connection: %v", err)
}

// --------------------------------------------------------------------------
// TestRequestIDsAreSequential
// --------------------------------------------------------------------------

func TestRequestIDsAreSequential(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	ids := make(chan string, 5)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for i := 0; i < 5; i++ {
			payload, err := readFrame(conn)
			if err != nil {
				return
			}
			var req rpcRequest
			json.Unmarshal(payload, &req)
			ids <- req.ID

			resp := rpcResponse{
				ID:     req.ID,
				Result: json.RawMessage(`"ok"`),
			}
			respBytes, _ := json.Marshal(resp)
			writeFrame(conn, respBytes)
		}
		close(ids)
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	for i := 0; i < 5; i++ {
		if _, err := c.Request("m", nil); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}

	// Collect and verify IDs are sequential starting from 1.
	expected := 1
	for id := range ids {
		want := fmt.Sprintf("%d", expected)
		if id != want {
			t.Errorf("expected id %s, got %s", want, id)
		}
		expected++
	}
}

// --------------------------------------------------------------------------
// TestRequestTimeout (server delays beyond what is reasonable)
// --------------------------------------------------------------------------

func TestRequestWriteAfterClose(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Immediately close to simulate disconnect.
		conn.Close()
	}()

	// Small delay to allow the server goroutine to accept and close.
	time.Sleep(50 * time.Millisecond)

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		// Connection refused or reset is acceptable.
		t.Logf("NewClient failed as expected: %v", err)
		return
	}
	defer c.Close()

	_, err = c.Request("testMethod", nil)
	if err == nil {
		t.Fatal("expected error writing to closed connection, got nil")
	}
	t.Logf("correctly detected write-after-close: %v", err)
}

// --------------------------------------------------------------------------
// TestValidPort
// --------------------------------------------------------------------------

func TestValidPort(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{0, false},
		{-1, false},
		{1, true},
		{80, true},
		{8765, true},
		{65535, true},
		{65536, false},
		{100000, false},
	}
	for _, tt := range tests {
		if got := ValidPort(tt.port); got != tt.want {
			t.Errorf("ValidPort(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// TestNewClientInvalidPort
// --------------------------------------------------------------------------

func TestNewClientInvalidPort(t *testing.T) {
	_, err := NewClient("127.0.0.1", 0, "")
	if err == nil {
		t.Fatal("expected error for port 0, got nil")
	}
	_, err = NewClient("127.0.0.1", -1, "")
	if err == nil {
		t.Fatal("expected error for port -1, got nil")
	}
	_, err = NewClient("127.0.0.1", 70000, "")
	if err == nil {
		t.Fatal("expected error for port 70000, got nil")
	}
}

// --------------------------------------------------------------------------
// TestScanPortsInvalidRange
// --------------------------------------------------------------------------

func TestScanPortsInvalidRange(t *testing.T) {
	mc := &MultiClient{
		defaultPort: 8765,
		host:        "127.0.0.1",
		clients:     make(map[int]*GhidraClient),
	}

	// startPort > endPort
	results := mc.ScanPorts(100, 50)
	if results != nil {
		t.Errorf("expected nil for invalid range, got %v", results)
	}

	// Invalid port 0
	results = mc.ScanPorts(0, 10)
	if results != nil {
		t.Errorf("expected nil for port 0, got %v", results)
	}
}

// --------------------------------------------------------------------------
// TestNewClientWithRetryExhausted
// --------------------------------------------------------------------------

func TestNewClientWithRetryExhausted(t *testing.T) {
	// Pick a port that nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(ln)
	ln.Close()

	cfg := RetryConfig{
		MaxRetries:     2,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	}

	start := time.Now()
	_, err = NewClientWithRetry("127.0.0.1", port, "", cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error after exhausting retries, got nil")
	}
	// Should have taken at least 10ms (1st backoff) + 20ms (2nd backoff) = 30ms
	if elapsed < 20*time.Millisecond {
		t.Errorf("expected retries to take some time, elapsed: %v", elapsed)
	}
	t.Logf("correctly failed after retries (elapsed %v): %v", elapsed, err)
}

// --------------------------------------------------------------------------
// TestReconnectOnNetworkError
// --------------------------------------------------------------------------

func TestReconnectOnNetworkError(t *testing.T) {
	// Start first server — handles one request then closes the connection
	ln := startFakeServer(t)
	defer ln.Close()

	requestCount := 0
	var serverMu sync.Mutex

	// Server: handle requests. After first request, close connection to simulate disconnect.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			// Handle one request per connection
			payload, err := readFrame(conn)
			if err != nil {
				conn.Close()
				continue
			}
			var req rpcRequest
			json.Unmarshal(payload, &req)

			resp := rpcResponse{
				ID:     req.ID,
				Result: json.RawMessage(`"ok"`),
			}
			respBytes, _ := json.Marshal(resp)
			writeFrame(conn, respBytes)

			serverMu.Lock()
			requestCount++
			count := requestCount
			serverMu.Unlock()

			// After first request, close connection to force reconnect
			if count == 1 {
				conn.Close()
			}
			// On subsequent connections, keep handling
			if count > 1 {
				// Handle more requests on this connection
				for {
					payload, err := readFrame(conn)
					if err != nil {
						conn.Close()
						break
					}
					json.Unmarshal(payload, &req)
					resp.ID = req.ID
					respBytes, _ = json.Marshal(resp)
					if err := writeFrame(conn, respBytes); err != nil {
						conn.Close()
						break
					}
				}
			}
		}
	}()

	// Connect to the server
	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	// First request should succeed
	_, err = c.Request("firstCall", nil)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	// Second request should trigger auto-reconnect (connection was closed)
	_, err = c.Request("secondCall", nil)
	if err != nil {
		t.Fatalf("second request (after reconnect) failed: %v", err)
	}
}

// --------------------------------------------------------------------------
// TestReconnectWhenClosed
// --------------------------------------------------------------------------

func TestReconnectWhenClosed(t *testing.T) {
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Don't respond — just accept the connection
		time.Sleep(2 * time.Second)
	}()

	c, err := NewClient("127.0.0.1", portOf(ln), "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Close the client deliberately
	c.Close()

	// Now try to reconnect — should fail because client is closed
	c.mu.Lock()
	err = c.reconnect()
	c.mu.Unlock()

	if err == nil {
		t.Fatal("expected reconnect to fail on closed client, got nil")
	}
	t.Logf("correctly refused reconnect after Close(): %v", err)
}

// --------------------------------------------------------------------------
// TestDefaultRetryConfig
// --------------------------------------------------------------------------

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()
	if cfg.MaxRetries != 10 {
		t.Errorf("expected MaxRetries=10, got %d", cfg.MaxRetries)
	}
	if cfg.InitialBackoff != 1*time.Second {
		t.Errorf("expected InitialBackoff=1s, got %v", cfg.InitialBackoff)
	}
	if cfg.MaxBackoff != 30*time.Second {
		t.Errorf("expected MaxBackoff=30s, got %v", cfg.MaxBackoff)
	}
}

// --------------------------------------------------------------------------
// TestIsNetworkError
// --------------------------------------------------------------------------

func TestIsNetworkError(t *testing.T) {
	// nil is not a network error
	if isNetworkError(nil) {
		t.Error("nil should not be a network error")
	}

	// EOF is a network error
	if !isNetworkError(io.EOF) {
		t.Error("io.EOF should be a network error")
	}

	// io.ErrUnexpectedEOF is a network error
	if !isNetworkError(io.ErrUnexpectedEOF) {
		t.Error("io.ErrUnexpectedEOF should be a network error")
	}

	// net.OpError is a network error
	opErr := &net.OpError{Op: "read", Err: fmt.Errorf("connection reset")}
	if !isNetworkError(opErr) {
		t.Error("net.OpError should be a network error")
	}

	// Application-level ghidra error is NOT a network error
	appErr := fmt.Errorf("ghidra error: function not found")
	if isNetworkError(appErr) {
		t.Error("application error should not be a network error")
	}

	// Error containing "broken pipe" is a network error
	pipeErr := fmt.Errorf("write payload: broken pipe")
	if !isNetworkError(pipeErr) {
		t.Error("broken pipe error should be a network error")
	}
}

// --------------------------------------------------------------------------
// TestMultiClientLazyConnect
// --------------------------------------------------------------------------

func TestMultiClientLazyConnect(t *testing.T) {
	// Start two fake servers on different ports.
	ln1 := startFakeServer(t)
	defer ln1.Close()
	ln2 := startFakeServer(t)
	defer ln2.Close()

	// Fake server handler (reusable)
	handleConn := func(ln net.Listener, marker string) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					payload, err := readFrame(c)
					if err != nil {
						return
					}
					var req rpcRequest
					json.Unmarshal(payload, &req)

					resp := rpcResponse{
						ID:     req.ID,
						Result: json.RawMessage(fmt.Sprintf(`"%s"`, marker)),
					}
					respBytes, _ := json.Marshal(resp)
					if err := writeFrame(c, respBytes); err != nil {
						return
					}
				}
			}(conn)
		}
	}

	go handleConn(ln1, "server1")
	go handleConn(ln2, "server2")

	// Create multi-client connecting to server 1 as default
	mc, err := NewMultiClient("127.0.0.1", portOf(ln1), "")
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	defer mc.CloseAll()

	// Request to default port
	result1, err := mc.Request("test", nil, 0)
	if err != nil {
		t.Fatalf("Request to default port: %v", err)
	}
	var s1 string
	json.Unmarshal(result1, &s1)
	if s1 != "server1" {
		t.Errorf("expected server1, got %s", s1)
	}

	// Request to second port (lazy connect)
	result2, err := mc.Request("test", nil, portOf(ln2))
	if err != nil {
		t.Fatalf("Request to second port: %v", err)
	}
	var s2 string
	json.Unmarshal(result2, &s2)
	if s2 != "server2" {
		t.Errorf("expected server2, got %s", s2)
	}
}

// --------------------------------------------------------------------------
// TestScanPortsFindsServer
// --------------------------------------------------------------------------

func TestScanPortsFindsServer(t *testing.T) {
	// Start a fake server that responds to "ping" with "pong"
	ln := startFakeServer(t)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				payload, err := readFrame(c)
				if err != nil {
					return
				}
				var req rpcRequest
				json.Unmarshal(payload, &req)

				if req.Method == "ping" {
					resp := rpcResponse{
						ID:     req.ID,
						Result: json.RawMessage(`"pong"`),
					}
					respBytes, _ := json.Marshal(resp)
					writeFrame(c, respBytes)
				}
			}(conn)
		}
	}()

	port := portOf(ln)

	mc, err := NewMultiClient("127.0.0.1", port, "")
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	defer mc.CloseAll()

	// Scan a narrow range that includes our server
	results := mc.ScanPorts(port, port)
	if len(results) != 1 {
		t.Fatalf("expected 1 result from scan, got %d", len(results))
	}
	if results[0]["port"] != port {
		t.Errorf("expected port %d, got %v", port, results[0]["port"])
	}
	if results[0]["status"] != "active" {
		t.Errorf("expected status 'active', got %v", results[0]["status"])
	}
}
