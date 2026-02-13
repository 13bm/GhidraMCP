package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ==========================================================================
// optionalPagination tests
//
// Since mcp-go v0.29+, optionalPagination takes a CallToolRequest (which
// wraps typed accessors) instead of a raw map. We construct requests via
// JSON-RPC to test the full path.
// ==========================================================================

// buildCallToolRequest constructs a CallToolRequest from a map of arguments.
func buildCallToolRequest(args map[string]interface{}) mcp.CallToolRequest {
	var req mcp.CallToolRequest
	if args != nil {
		req.Params.Arguments = args
	}
	return req
}

func TestOptionalPaginationBothPresent(t *testing.T) {
	req := buildCallToolRequest(map[string]interface{}{
		"offset": float64(10),
		"limit":  float64(50),
	})
	params := map[string]interface{}{}
	optionalPagination(req, params)

	if params["offset"] != 10 {
		t.Errorf("expected offset=10, got %v", params["offset"])
	}
	if params["limit"] != 50 {
		t.Errorf("expected limit=50, got %v", params["limit"])
	}
}

func TestOptionalPaginationOnlyOffset(t *testing.T) {
	req := buildCallToolRequest(map[string]interface{}{
		"offset": float64(5),
	})
	params := map[string]interface{}{}
	optionalPagination(req, params)

	if params["offset"] != 5 {
		t.Errorf("expected offset=5, got %v", params["offset"])
	}
	if _, exists := params["limit"]; exists {
		t.Error("limit should not be set when absent from args")
	}
}

func TestOptionalPaginationOnlyLimit(t *testing.T) {
	req := buildCallToolRequest(map[string]interface{}{
		"limit": float64(25),
	})
	params := map[string]interface{}{}
	optionalPagination(req, params)

	if _, exists := params["offset"]; exists {
		t.Error("offset should not be set when absent from args")
	}
	if params["limit"] != 25 {
		t.Errorf("expected limit=25, got %v", params["limit"])
	}
}

func TestOptionalPaginationNeitherPresent(t *testing.T) {
	req := buildCallToolRequest(map[string]interface{}{
		"query": "some search",
	})
	params := map[string]interface{}{}
	optionalPagination(req, params)

	if _, exists := params["offset"]; exists {
		t.Error("offset should not be set")
	}
	if _, exists := params["limit"]; exists {
		t.Error("limit should not be set")
	}
}

func TestOptionalPaginationEmptyArgs(t *testing.T) {
	req := buildCallToolRequest(map[string]interface{}{})
	params := map[string]interface{}{}
	optionalPagination(req, params)

	if len(params) != 0 {
		t.Errorf("expected empty params, got %v", params)
	}
}

func TestOptionalPaginationPreservesExistingParams(t *testing.T) {
	req := buildCallToolRequest(map[string]interface{}{
		"offset": float64(3),
		"limit":  float64(10),
	})
	params := map[string]interface{}{
		"query": "existing",
	}
	optionalPagination(req, params)

	if params["query"] != "existing" {
		t.Error("existing params should be preserved")
	}
	if params["offset"] != 3 {
		t.Errorf("expected offset=3, got %v", params["offset"])
	}
	if params["limit"] != 10 {
		t.Errorf("expected limit=10, got %v", params["limit"])
	}
}

// ==========================================================================
// registerAllTools tests
// ==========================================================================

func TestRegisterAllToolsDoesNotPanic(t *testing.T) {
	s := server.NewMCPServer("TestGhidraMCP", "1.0.0-test")
	// registerAllTools should not panic.
	registerAllTools(s)
}

func TestRegisterAllToolsRegistersExpectedToolCount(t *testing.T) {
	s := server.NewMCPServer("TestGhidraMCP", "1.0.0-test")
	registerAllTools(s)

	// Use HandleMessage to send a tools/list JSON-RPC request.
	listReq := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	resp := s.HandleMessage(context.Background(), json.RawMessage(listReq))
	if resp == nil {
		t.Fatal("HandleMessage returned nil for tools/list")
	}

	// Marshal and re-parse to get the tool count.
	respBytes, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var parsed struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if parsed.Error != nil {
		t.Fatalf("tools/list returned error: %s", parsed.Error.Message)
	}

	// 61 original tools (numbering skips #4) + 1 list_ghidra_instances +
	// 5 struct CRUD tools + 2 async decompilation tools = 69.
	const expectedTools = 69
	if len(parsed.Result.Tools) != expectedTools {
		t.Errorf("expected %d tools registered, got %d", expectedTools, len(parsed.Result.Tools))
	}
}

func TestRegisterAllToolsContainsExpectedNames(t *testing.T) {
	s := server.NewMCPServer("TestGhidraMCP", "1.0.0-test")
	registerAllTools(s)

	listReq := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	resp := s.HandleMessage(context.Background(), json.RawMessage(listReq))

	respBytes, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var parsed struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	toolNames := make(map[string]bool)
	for _, tool := range parsed.Result.Tools {
		toolNames[tool.Name] = true
	}

	// Check a representative sample of tools across all categories.
	expected := []string{
		"list_functions",             // 1 - query tools
		"list_classes",               // 2
		"list_imports",               // 3
		"list_exports",               // 5
		"search_functions_by_name",   // 9
		"decompile_function",         // 13
		"get_program_info",           // 19
		"rename_function",            // 22 - mutation tools
		"set_decompiler_comment",     // 26
		"create_structure",           // 33
		"patch_bytes",                // 39 - advanced analysis
		"extract_api_call_sequences", // 41
		"generate_call_graph",        // 43
		"search_bytes",               // 46 - malware analysis
		"emulate_function",           // 47
		"extract_iocs",               // 48
		"detect_anti_analysis",       // 50
		"get_pe_info",                // 52
		"create_memory_block",        // 54 - IoT/embedded
		"find_rop_gadgets",           // 57
		"get_bookmarks",              // 60 - utility
		"list_equates",               // 61
		"ping",                       // 62
		"list_ghidra_instances",      // 63 - multi-instance
		"get_structure",              // 64 - struct CRUD
		"list_structures",            // 65
		"edit_structure",             // 66
		"rename_structure",           // 67
		"delete_structure",           // 68
		"decompile_function_async",   // 69 - async decompilation
		"get_decompile_result",       // 70
	}

	for _, name := range expected {
		if !toolNames[name] {
			t.Errorf("expected tool %q to be registered, but it was not found", name)
		}
	}
}

func TestDataDrivenRequiredParamValidation(t *testing.T) {
	// Tools with required string params should return an error when the param
	// is empty (i.e. not supplied).
	handler := buildHandler(toolDef{
		Name:   "test_tool",
		Method: "testMethod",
		Params: []paramDef{
			{MCPName: "name", Desc: "test", Type: paramString, Required: true},
		},
	})

	// Build a request with an empty "name" param.
	req := buildCallToolRequest(map[string]interface{}{
		"name": "",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	// The result should be an error tool result (isError=true).
	respBytes, _ := json.Marshal(result)
	respStr := string(respBytes)
	if !result.IsError {
		t.Errorf("expected error result for empty required param, got: %s", respStr)
	}
}

func TestDataDrivenJSONParseParam(t *testing.T) {
	handler := buildHandler(toolDef{
		Name:   "test_tool",
		Method: "testMethod",
		Params: []paramDef{
			{MCPName: "data", RPCName: "data", Desc: "test", Type: paramJSONParse, Required: true},
		},
	})

	// Test with invalid JSON — should return error.
	req := buildCallToolRequest(map[string]interface{}{
		"data": "not valid json",
	})
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for invalid JSON param")
	}
}

func TestDataDrivenToolCount(t *testing.T) {
	// Verify the allTools slice matches expected count.
	const expectedTools = 69
	if len(allTools) != expectedTools {
		t.Errorf("expected %d tools in allTools, got %d", expectedTools, len(allTools))
	}
}

func TestRegisterAllToolsIdempotent(t *testing.T) {
	s := server.NewMCPServer("TestGhidraMCP", "1.0.0-test")

	// Call twice -- should not panic or produce duplicates.
	registerAllTools(s)
	registerAllTools(s)

	listReq := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	resp := s.HandleMessage(context.Background(), json.RawMessage(listReq))

	respBytes, _ := json.Marshal(resp)
	var parsed struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	json.Unmarshal(respBytes, &parsed)

	// AddTool uses map keyed by name, so duplicates should not accumulate.
	const expectedTools = 69
	if len(parsed.Result.Tools) != expectedTools {
		t.Errorf("after double registration, expected %d tools, got %d",
			expectedTools, len(parsed.Result.Tools))
	}
}
