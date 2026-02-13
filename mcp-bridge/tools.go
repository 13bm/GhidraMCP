// Data-driven tool definitions for GhidraMCP Bridge.
//
// Each tool is declared as a toolDef struct. The registration engine in
// registerAllTools() uses these definitions to generate MCP tools with
// consistent parameter handling, pagination, target_port routing, and
// annotation boilerplate — eliminating ~1200 lines of repetitive code.
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ---------------------------------------------------------------------------
// Parameter types for the declarative tool DSL
// ---------------------------------------------------------------------------

// paramType determines how a parameter is extracted from the MCP request
// and placed into the Ghidra RPC params map.
type paramType int

const (
	paramString    paramType = iota // extracted via GetString
	paramNumber                    // extracted via GetInt
	paramFloat                     // extracted via GetFloat, forwarded as int64
	paramBool                      // extracted via GetBool
	paramJSONParse                 // string input that must be JSON-parsed before forwarding
)

// paramDef describes a single tool parameter.
type paramDef struct {
	MCPName    string    // name as seen by the MCP client (snake_case)
	RPCName    string    // name sent to Ghidra Java side (camelCase); empty = same as MCPName
	Desc       string    // description shown to the user
	Type       paramType // how to extract and forward the value
	Required   bool      // whether mcp.Required() is added
	DefaultInt int       // default for paramNumber (sentinel: -1 means "not supplied")
}

// rpcName returns the Ghidra-side parameter name.
func (p paramDef) rpcName() string {
	if p.RPCName != "" {
		return p.RPCName
	}
	return p.MCPName
}

// toolDef is the declarative specification for one MCP tool.
type toolDef struct {
	Name        string     // MCP tool name (snake_case)
	Desc        string     // tool description
	Title       string     // annotation title
	Method      string     // Ghidra RPC method name
	ReadOnly    bool       // readOnlyHint annotation
	Destructive bool       // destructiveHint annotation
	Paginated   bool       // adds offset/limit params and optionalPagination extraction
	Params      []paramDef // tool-specific parameters (target_port added automatically)
	// Custom is set for tools that cannot be expressed declaratively.
	// When non-nil, the registration engine registers this handler directly
	// and ignores Method/Params/Paginated.
	Custom func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
	// ExtraOpts are additional mcp.ToolOption values (e.g. extra WithBoolean
	// or WithString for optional params that need special handling in Custom).
	ExtraOpts []mcp.ToolOption
}

// ---------------------------------------------------------------------------
// Registration engine
// ---------------------------------------------------------------------------

// registerAllTools registers every tool from the allTools slice.
func registerAllTools(s *server.MCPServer) {
	for _, t := range allTools {
		tool := buildTool(t)
		handler := buildHandler(t)
		s.AddTool(tool, handler)
	}
}

// buildTool constructs the mcp.Tool from a toolDef.
func buildTool(t toolDef) mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription(t.Desc),
		mcp.WithTitleAnnotation(t.Title),
		mcp.WithReadOnlyHintAnnotation(t.ReadOnly),
		mcp.WithDestructiveHintAnnotation(!t.ReadOnly),
	}

	// Add declared parameters.
	for _, p := range t.Params {
		switch p.Type {
		case paramString, paramJSONParse:
			if p.Required {
				opts = append(opts, mcp.WithString(p.MCPName, mcp.Required(), mcp.Description(p.Desc)))
			} else {
				opts = append(opts, mcp.WithString(p.MCPName, mcp.Description(p.Desc)))
			}
		case paramNumber:
			if p.Required {
				opts = append(opts, mcp.WithNumber(p.MCPName, mcp.Required(), mcp.Description(p.Desc)))
			} else {
				opts = append(opts, mcp.WithNumber(p.MCPName, mcp.Description(p.Desc)))
			}
		case paramFloat:
			if p.Required {
				opts = append(opts, mcp.WithNumber(p.MCPName, mcp.Required(), mcp.Description(p.Desc)))
			} else {
				opts = append(opts, mcp.WithNumber(p.MCPName, mcp.Description(p.Desc)))
			}
		case paramBool:
			if p.Required {
				opts = append(opts, mcp.WithBoolean(p.MCPName, mcp.Required(), mcp.Description(p.Desc)))
			} else {
				opts = append(opts, mcp.WithBoolean(p.MCPName, mcp.Description(p.Desc)))
			}
		}
	}

	// Add pagination parameters.
	if t.Paginated {
		opts = append(opts,
			mcp.WithNumber("offset", mcp.Description("Number of items to skip for pagination")),
			mcp.WithNumber("limit", mcp.Description("Maximum number of items to return")),
		)
	}

	// Append any extra options (e.g. for custom tools that still want some
	// declarative parameters alongside their custom handler).
	opts = append(opts, t.ExtraOpts...)

	// All routable tools get target_port; skip for non-forwarding tools.
	if t.Method != "" || t.Custom == nil {
		opts = append(opts, mcp.WithNumber("target_port",
			mcp.Description("Optional port of a specific Ghidra instance (0 or omit for default)")))
	}

	return mcp.NewTool(t.Name, opts...)
}

// buildHandler constructs the tool handler function from a toolDef.
func buildHandler(t toolDef) server.ToolHandlerFunc {
	if t.Custom != nil {
		return t.Custom
	}

	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := make(map[string]interface{})

		// Extract declared parameters.
		for _, p := range t.Params {
			switch p.Type {
			case paramString:
				v := req.GetString(p.MCPName, "")
				if p.Required && v == "" {
					return mcp.NewToolResultError(fmt.Sprintf("required parameter %q is empty", p.MCPName)), nil
				}
				if v != "" || p.Required {
					params[p.rpcName()] = v
				}
			case paramJSONParse:
				raw := req.GetString(p.MCPName, "")
				if p.Required && raw == "" {
					return mcp.NewToolResultError(fmt.Sprintf("required parameter %q is empty", p.MCPName)), nil
				}
				if raw != "" {
					var parsed interface{}
					if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
						return mcp.NewToolResultError(fmt.Sprintf("invalid JSON for %q: %v", p.MCPName, err)), nil
					}
					params[p.rpcName()] = parsed
				}
			case paramNumber:
				sentinel := -1
				if p.DefaultInt != 0 {
					sentinel = p.DefaultInt
				}
				if p.Required {
					params[p.rpcName()] = req.GetInt(p.MCPName, sentinel)
				} else {
					if v := req.GetInt(p.MCPName, -1); v >= 0 {
						params[p.rpcName()] = v
					}
				}
			case paramFloat:
				v := int64(req.GetFloat(p.MCPName, 0))
				params[p.rpcName()] = v
			case paramBool:
				if p.Required {
					params[p.rpcName()] = req.GetBool(p.MCPName, false)
				} else {
					if v := req.GetBool(p.MCPName, false); v {
						params[p.rpcName()] = v
					}
				}
			}
		}

		// Apply pagination if the tool supports it.
		if t.Paginated {
			optionalPagination(req, params)
		}

		return forwardWithTargetPort(req, t.Method, params)
	}
}

// ---------------------------------------------------------------------------
// Tool definitions (69 tools)
// ---------------------------------------------------------------------------

var allTools = []toolDef{
	// =====================================================================
	// READ-ONLY QUERY TOOLS (1-21)
	// =====================================================================
	{Name: "list_functions", Desc: "List all functions in the current program with their entry points, sizes, and return types. Supports pagination with offset and limit.", Title: "List Functions", Method: "getAllFunctions", ReadOnly: true, Paginated: true},
	{Name: "list_classes", Desc: "List all classes/namespaces defined in the current program. Supports pagination.", Title: "List Classes", Method: "listClasses", ReadOnly: true, Paginated: true},
	{Name: "list_imports", Desc: "List all imported symbols and functions from external libraries. Useful for understanding the binary's dependencies.", Title: "List Imports", Method: "getImports", ReadOnly: true, Paginated: true},
	{Name: "list_exports", Desc: "List all exported symbols from the binary. These are the entry points available to other programs or libraries.", Title: "List Exports", Method: "getExports", ReadOnly: true, Paginated: true},
	{Name: "list_namespaces", Desc: "List all namespaces in the program. Namespaces organize symbols into logical groups (classes, modules, etc.).", Title: "List Namespaces", Method: "listNamespaces", ReadOnly: true, Paginated: true},
	{Name: "list_data_items", Desc: "List all defined data items in the program (globals, constants, arrays, structs, etc.) with their addresses and types.", Title: "List Data Items", Method: "listDataItems", ReadOnly: true, Paginated: true},

	{Name: "list_strings", Desc: "List defined strings in the binary. Optionally filter by a case-insensitive substring match. Supports pagination.", Title: "List Strings", Method: "getStrings", ReadOnly: true, Paginated: true,
		Params: []paramDef{{MCPName: "filter", Desc: "Optional case-insensitive substring filter on string content", Type: paramString}},
	},

	{Name: "search_functions_by_name", Desc: "Search for functions whose name contains the given query string. Useful for finding functions related to a specific feature or API.", Title: "Search Functions", Method: "searchFunctionsByName", ReadOnly: true, Paginated: true,
		Params: []paramDef{{MCPName: "query", Desc: "Substring to search for in function names", Type: paramString, Required: true}},
	},

	{Name: "get_function_by_address", Desc: "Get detailed information about a function at the given address, including name, parameters, callers, and callees.", Title: "Get Function", Method: "getFunctionByAddress", ReadOnly: true,
		Params: []paramDef{{MCPName: "address", Desc: "Address of the function (e.g. '0x00401000')", Type: paramString, Required: true}},
	},

	{Name: "get_current_address", Desc: "Get the address currently selected in Ghidra's listing view. Useful for understanding where the analyst is looking.", Title: "Get Current Address", Method: "getCurrentAddress", ReadOnly: true},
	{Name: "get_current_function", Desc: "Get information about the function that contains the currently selected address in Ghidra's listing view.", Title: "Get Current Function", Method: "getCurrentFunction", ReadOnly: true},

	{Name: "decompile_function", Desc: "Decompile a function by its name and return the C pseudocode. Useful for understanding what a named function does.", Title: "Decompile Function", Method: "decompileFunctionByName", ReadOnly: true,
		Params: []paramDef{{MCPName: "name", Desc: "Name of the function to decompile", Type: paramString, Required: true}},
	},

	{Name: "decompile_function_by_address", Desc: "Decompile a function at the given address and return the C pseudocode. Essential for understanding function logic.", Title: "Decompile by Address", Method: "getDecompiledCode", ReadOnly: true,
		Params: []paramDef{{MCPName: "address", Desc: "Address of the function to decompile (e.g. '0x00401000')", Type: paramString, Required: true}},
	},

	{Name: "disassemble_function", Desc: "Get the assembly instructions for a function at the given address. Returns the raw disassembly listing.", Title: "Disassemble Function", Method: "disassembleFunction", ReadOnly: true,
		Params: []paramDef{{MCPName: "address", Desc: "Address of the function to disassemble (e.g. '0x00401000')", Type: paramString, Required: true}},
	},

	{Name: "get_xrefs_to", Desc: "Get all cross-references TO a given address. Shows what code references this location (callers, data readers, etc.).", Title: "Get XRefs To", Method: "getXrefsTo", ReadOnly: true, Paginated: true,
		Params: []paramDef{{MCPName: "address", Desc: "Target address to find references to", Type: paramString, Required: true}},
	},
	{Name: "get_xrefs_from", Desc: "Get all cross-references FROM a given address. Shows what this location references (callees, data writes, etc.).", Title: "Get XRefs From", Method: "getXrefsFrom", ReadOnly: true, Paginated: true,
		Params: []paramDef{{MCPName: "address", Desc: "Source address to find references from", Type: paramString, Required: true}},
	},
	{Name: "get_function_xrefs", Desc: "Get all cross-references for a function by name, including both callers and callees.", Title: "Get Function XRefs", Method: "getFunctionXrefs", ReadOnly: true, Paginated: true,
		Params: []paramDef{{MCPName: "name", Desc: "Name of the function", Type: paramString, Required: true}},
	},

	{Name: "get_program_info", Desc: "Get metadata about the currently loaded program: name, architecture, compiler, executable format, creation date, and function count.", Title: "Get Program Info", Method: "getContext", ReadOnly: true},

	{Name: "get_memory_map", Desc: "Get the full memory layout of the binary, including all segments with start/end addresses, sizes, and permission flags (RWX).", Title: "Get Memory Map", Method: "getMemoryMap", ReadOnly: true, Paginated: true},

	{Name: "get_variables", Desc: "Get all variables (parameters and locals) for a function at the given address, including names, types, storage locations, and stack offsets.", Title: "Get Variables", Method: "getVariables", ReadOnly: true,
		Params: []paramDef{{MCPName: "function_address", RPCName: "functionAddress", Desc: "Address of the function", Type: paramString, Required: true}},
	},

	// =====================================================================
	// MUTATION TOOLS (22-38)
	// =====================================================================
	{Name: "rename_function", Desc: "Rename a function by its current name. Assigns a new user-defined name to make the function more readable.", Title: "Rename Function", Method: "renameFunction",
		Params: []paramDef{
			{MCPName: "old_name", RPCName: "currentName", Desc: "Current name of the function", Type: paramString, Required: true},
			{MCPName: "new_name", RPCName: "newName", Desc: "New name to assign to the function", Type: paramString, Required: true},
		},
	},
	{Name: "rename_function_by_address", Desc: "Rename a function by its address. Useful when the function has an auto-generated name like FUN_00401000.", Title: "Rename Function", Method: "renameFunction",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address of the function to rename", Type: paramString, Required: true},
			{MCPName: "new_name", RPCName: "newName", Desc: "New name to assign to the function", Type: paramString, Required: true},
		},
	},
	{Name: "rename_data", Desc: "Rename a data label at the specified address. Assigns a meaningful name to a global variable, string, or constant.", Title: "Rename Data", Method: "renameData",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address of the data item", Type: paramString, Required: true},
			{MCPName: "new_name", RPCName: "newName", Desc: "New name to assign", Type: paramString, Required: true},
		},
	},
	{Name: "rename_variable", Desc: "Rename a local variable or parameter within a function to improve decompiler output readability.", Title: "Rename Variable", Method: "renameVariable",
		Params: []paramDef{
			{MCPName: "function_address", RPCName: "functionAddress", Desc: "Address of the function containing the variable", Type: paramString, Required: true},
			{MCPName: "old_name", RPCName: "oldName", Desc: "Current name of the variable", Type: paramString, Required: true},
			{MCPName: "new_name", RPCName: "newName", Desc: "New name for the variable", Type: paramString, Required: true},
		},
	},
	{Name: "set_decompiler_comment", Desc: "Set a comment that appears in the decompiler view at the specified address. Useful for annotating decompiled code.", Title: "Set Comment", Method: "setDecompilerComment",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address where the comment should appear", Type: paramString, Required: true},
			{MCPName: "comment", Desc: "Comment text to set", Type: paramString, Required: true},
		},
	},
	{Name: "set_disassembly_comment", Desc: "Set a comment that appears in the disassembly listing view at the specified address. Useful for annotating assembly code.", Title: "Set Comment", Method: "setDisassemblyComment",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address where the comment should appear", Type: paramString, Required: true},
			{MCPName: "comment", Desc: "Comment text to set", Type: paramString, Required: true},
		},
	},
	{Name: "set_function_prototype", Desc: "Set the full function prototype (return type, name, and parameters) for a function. Example: 'int myFunc(char *buf, int len)'", Title: "Set Prototype", Method: "setFunctionPrototype",
		Params: []paramDef{
			{MCPName: "function_address", RPCName: "functionAddress", Desc: "Address of the function", Type: paramString, Required: true},
			{MCPName: "prototype", Desc: "Full C-style function prototype string", Type: paramString, Required: true},
		},
	},
	{Name: "set_local_variable_type", Desc: "Change the data type of a local variable in a function. Improves decompiler output accuracy.", Title: "Set Variable Type", Method: "setLocalVariableType",
		Params: []paramDef{
			{MCPName: "function_address", RPCName: "functionAddress", Desc: "Address of the function containing the variable", Type: paramString, Required: true},
			{MCPName: "variable_name", RPCName: "variableName", Desc: "Name of the variable to retype", Type: paramString, Required: true},
			{MCPName: "new_type", RPCName: "newType", Desc: "New data type (e.g. 'int', 'char *', 'DWORD')", Type: paramString, Required: true},
		},
	},
	{Name: "set_bookmark", Desc: "Set a bookmark at the given address. Bookmarks help track interesting locations for later review.", Title: "Set Bookmark", Method: "setBookmark",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address to bookmark", Type: paramString, Required: true},
			{MCPName: "type", Desc: "Bookmark type (e.g. 'Note', 'Warning', 'Error', 'Info')", Type: paramString, Required: true},
			{MCPName: "category", Desc: "Category for the bookmark", Type: paramString, Required: true},
			{MCPName: "comment", Desc: "Descriptive comment for the bookmark", Type: paramString, Required: true},
		},
	},
	{Name: "remove_bookmark", Desc: "Remove a bookmark at the given address matching the specified type and category.", Title: "Remove Bookmark", Method: "removeBookmark",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address of the bookmark to remove", Type: paramString, Required: true},
			{MCPName: "type", Desc: "Bookmark type to match", Type: paramString, Required: true},
			{MCPName: "category", Desc: "Bookmark category to match", Type: paramString, Required: true},
		},
	},

	// set_equate has mixed param types (string + int + float-as-int64)
	{Name: "set_equate", Desc: "Set an equate (named constant) on a scalar operand at the given address. Replaces magic numbers with meaningful names.", Title: "Set Equate", Method: "setEquate",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address of the instruction containing the operand", Type: paramString, Required: true},
			{MCPName: "operand_index", RPCName: "operandIndex", Desc: "Index of the operand (0-based)", Type: paramNumber, Required: true},
			{MCPName: "name", Desc: "Name for the equate", Type: paramString, Required: true},
			{MCPName: "value", Desc: "Numeric value the equate represents", Type: paramFloat, Required: true},
		},
	},

	// create_structure: fields param is JSON-parsed
	{Name: "create_structure", Desc: "Create a new structure data type with the given name and fields. Fields should be a JSON array of {name, type, size} objects.", Title: "Create Structure", Method: "createStructure",
		Params: []paramDef{
			{MCPName: "name", Desc: "Name for the new structure", Type: paramString, Required: true},
			{MCPName: "fields", Desc: `JSON array of field definitions, e.g. [{"name":"x","type":"int","size":4}]`, Type: paramJSONParse, Required: true},
		},
	},

	// create_enum: values param is JSON-parsed, size is a number
	{Name: "create_enum", Desc: "Create a new enum data type with the given name, size, and values. Values should be a JSON object mapping names to numeric values.", Title: "Create Enum", Method: "createEnum",
		Params: []paramDef{
			{MCPName: "name", Desc: "Name for the new enum", Type: paramString, Required: true},
			{MCPName: "size", Desc: "Size of the enum in bytes (1, 2, 4, or 8)", Type: paramNumber, Required: true, DefaultInt: 4},
			{MCPName: "values", Desc: `JSON object mapping enum member names to values, e.g. {"OK":0,"ERROR":1}`, Type: paramJSONParse, Required: true},
		},
	},

	{Name: "apply_data_type", Desc: "Apply a data type at the given address. Changes how Ghidra interprets the bytes at that location (e.g. int, char[], struct).", Title: "Apply Data Type", Method: "applyDataType",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address where the type should be applied", Type: paramString, Required: true},
			{MCPName: "type_name", RPCName: "typeName", Desc: "Name of the data type to apply", Type: paramString, Required: true},
		},
	},
	{Name: "set_calling_convention", Desc: "Set the calling convention for a function (e.g. '__stdcall', '__cdecl', '__fastcall', '__thiscall').", Title: "Set Convention", Method: "setCallingConvention",
		Params: []paramDef{
			{MCPName: "function_address", RPCName: "functionAddress", Desc: "Address of the function", Type: paramString, Required: true},
			{MCPName: "convention", Desc: "Calling convention name", Type: paramString, Required: true},
		},
	},
	{Name: "set_image_base", Desc: "Set the image base address of the program. This rebases all addresses in the binary.", Title: "Set Image Base", Method: "setImageBase",
		Params: []paramDef{
			{MCPName: "new_base_address", RPCName: "newBaseAddress", Desc: "New base address for the image (e.g. '0x10000000')", Type: paramString, Required: true},
		},
	},

	// set_memory_permissions: mixed string + bool params
	{Name: "set_memory_permissions", Desc: "Set the read/write/execute permission flags for a memory block at the given address.", Title: "Set Permissions", Method: "setMemoryPermissions",
		Params: []paramDef{
			{MCPName: "address", Desc: "Start address of the memory block", Type: paramString, Required: true},
			{MCPName: "read", Desc: "Whether the memory block is readable", Type: paramBool, Required: true},
			{MCPName: "write", Desc: "Whether the memory block is writable", Type: paramBool, Required: true},
			{MCPName: "execute", Desc: "Whether the memory block is executable", Type: paramBool, Required: true},
			{MCPName: "is_volatile", RPCName: "isVolatile", Desc: "Whether the memory block is volatile (e.g. memory-mapped I/O)", Type: paramBool},
		},
	},

	// =====================================================================
	// ADVANCED ANALYSIS TOOLS (39-45)
	// =====================================================================
	{Name: "patch_bytes", Desc: "Write raw bytes to the binary at the given address. The bytes are specified as a hex string (e.g. '90909090' for NOP sled).", Title: "Patch Bytes", Method: "patchBytes",
		Params: []paramDef{
			{MCPName: "address", Desc: "Address to patch", Type: paramString, Required: true},
			{MCPName: "hex_bytes", RPCName: "hexBytes", Desc: "Hex-encoded bytes to write (e.g. '90909090')", Type: paramString, Required: true},
		},
	},
	{Name: "get_basic_blocks", Desc: "Get all basic blocks for a function at the given address. Returns the control flow graph as a list of blocks with their start/end addresses and successors.", Title: "Get Basic Blocks", Method: "getBasicBlocks", ReadOnly: true,
		Params: []paramDef{{MCPName: "function_address", RPCName: "functionAddress", Desc: "Address of the function to analyze", Type: paramString, Required: true}},
	},
	{Name: "extract_api_call_sequences", Desc: "Extract the sequence of external API calls made by a function, categorized by type (network, file, crypto, etc.) with security risk assessments.", Title: "Extract API Calls", Method: "extractApiCallSequences", ReadOnly: true,
		Params: []paramDef{{MCPName: "address", Desc: "Address of the function to analyze", Type: paramString, Required: true}},
	},
	{Name: "identify_user_input_sources", Desc: "Identify all potential sources of user/external input in the binary (scanf, recv, ReadFile, etc.). Useful for finding attack surfaces.", Title: "Find Input Sources", Method: "identifyUserInputSources", ReadOnly: true},

	{Name: "generate_call_graph", Desc: "Generate a hierarchical call graph starting from a function, up to the specified depth. Includes complexity metrics for each node.", Title: "Generate Call Graph", Method: "generateStructuredCallGraph", ReadOnly: true,
		Params: []paramDef{
			{MCPName: "address", Desc: "Address of the starting function", Type: paramString, Required: true},
			{MCPName: "max_depth", RPCName: "maxDepth", Desc: "Maximum depth to traverse the call graph", Type: paramNumber, Required: true, DefaultInt: 3},
		},
	},

	{Name: "identify_crypto_patterns", Desc: "Detect cryptographic implementations in the binary by analyzing function names, API usage, known constants (AES S-box, SHA-256 IVs), and code patterns.", Title: "Find Crypto Patterns", Method: "identifyCryptographicPatterns", ReadOnly: true},
	{Name: "find_obfuscated_strings", Desc: "Find strings that may be obfuscated, encoded, or constructed at runtime to evade static analysis. Detects XOR encoding, stack strings, and decryption routines.", Title: "Find Obfuscated Strings", Method: "findObfuscatedStrings", ReadOnly: true},

	// =====================================================================
	// MALWARE ANALYSIS TOOLS (46-53)
	// =====================================================================

	// search_bytes: has optional string/number params that need custom extraction
	{Name: "search_bytes", Desc: "Search for a byte pattern in the binary. Supports optional mask for wildcard bytes. Useful for finding signatures or shellcode.", Title: "Search Bytes", Method: "searchBytes", ReadOnly: true,
		Params: []paramDef{
			{MCPName: "pattern", Desc: "Hex byte pattern to search for (e.g. '4D5A9000')", Type: paramString, Required: true},
			{MCPName: "mask", Desc: "Optional hex mask where 'FF' means exact match and '00' means wildcard", Type: paramString},
			{MCPName: "start_address", RPCName: "startAddress", Desc: "Optional start address to begin search from", Type: paramString},
			{MCPName: "max_results", RPCName: "maxResults", Desc: "Maximum number of results to return", Type: paramNumber},
		},
	},

	// emulate_function: args param is JSON-parsed, max_steps is optional number
	{Name: "emulate_function", Desc: "Emulate execution of a function from the given address with optional arguments. Returns register state and memory changes after execution.", Title: "Emulate Function", Method: "emulateFunction", ReadOnly: true,
		Params: []paramDef{
			{MCPName: "address", Desc: "Address of the function to emulate", Type: paramString, Required: true},
			{MCPName: "args", Desc: "Optional JSON array of argument values to pass to the function", Type: paramJSONParse},
			{MCPName: "max_steps", RPCName: "maxSteps", Desc: "Maximum number of instructions to emulate (default: 10000)", Type: paramNumber},
		},
	},

	{Name: "extract_iocs", Desc: "Extract Indicators of Compromise (IOCs) from the binary: URLs, IP addresses, domain names, file paths, registry keys, mutexes, and email addresses.", Title: "Extract IOCs", Method: "extractIOCs", ReadOnly: true},
	{Name: "find_dynamic_api_resolution", Desc: "Find instances of dynamic API resolution (LoadLibrary/GetProcAddress patterns). Common in malware to hide imported functions from static analysis.", Title: "Find Dynamic APIs", Method: "findDynamicAPIResolution", ReadOnly: true},
	{Name: "detect_anti_analysis", Desc: "Detect anti-debugging, anti-VM, and anti-analysis techniques in the binary. Identifies checks for debuggers, virtual machines, sandboxes, and timing attacks.", Title: "Detect Anti-Analysis", Method: "detectAntiAnalysis", ReadOnly: true},

	{Name: "add_external_function", Desc: "Add an external function reference. Links an address in the binary to a known library function that was not automatically resolved.", Title: "Add External Func", Method: "addExternalFunction",
		Params: []paramDef{
			{MCPName: "library", Desc: "Name of the external library (e.g. 'kernel32.dll')", Type: paramString, Required: true},
			{MCPName: "function_name", RPCName: "functionName", Desc: "Name of the external function", Type: paramString, Required: true},
			{MCPName: "address", Desc: "Address where the function is referenced", Type: paramString, Required: true},
		},
	},

	{Name: "get_pe_info", Desc: "Get PE (Portable Executable) header information for Windows binaries: DOS header, PE signature, sections, imports/exports, resources, and timestamps.", Title: "Get PE Info", Method: "getPEInfo", ReadOnly: true},
	{Name: "get_elf_info", Desc: "Get ELF (Executable and Linkable Format) header information for Linux/Unix binaries: program headers, section headers, symbol tables, and dynamic linking info.", Title: "Get ELF Info", Method: "getELFInfo", ReadOnly: true},

	// =====================================================================
	// IoT / EMBEDDED SECURITY TOOLS (54-59)
	// =====================================================================

	// create_memory_block: mixed string + number + optional bool
	{Name: "create_memory_block", Desc: "Create a new memory block in the program. Useful for adding memory-mapped I/O regions or other memory areas in embedded firmware analysis.", Title: "Create Memory Block", Method: "createMemoryBlock",
		Params: []paramDef{
			{MCPName: "name", Desc: "Name for the memory block", Type: paramString, Required: true},
			{MCPName: "address", Desc: "Start address of the memory block", Type: paramString, Required: true},
			{MCPName: "size", Desc: "Size of the memory block in bytes", Type: paramNumber, Required: true},
			{MCPName: "permissions", Desc: "Permission string like 'rwx', 'r-x', 'rw-'", Type: paramString, Required: true},
			{MCPName: "is_overlay", RPCName: "isOverlay", Desc: "Whether to create as an overlay block (default: false)", Type: paramBool},
		},
	},

	{Name: "detect_security_mitigations", Desc: "Detect security mitigations present in the binary: stack canaries, ASLR/PIE, DEP/NX, RELRO, SafeSEH, Control Flow Guard, and more.", Title: "Detect Mitigations", Method: "detectSecurityMitigations", ReadOnly: true},
	{Name: "find_format_string_vulns", Desc: "Find potential format string vulnerabilities by detecting calls to printf-family functions where the format argument may be user-controlled.", Title: "Find Format Strings", Method: "findFormatStringVulns", ReadOnly: true},

	// find_rop_gadgets: optional number + optional string
	{Name: "find_rop_gadgets", Desc: "Find Return-Oriented Programming (ROP) gadgets in the binary. Useful for exploit development and understanding binary exploitation potential.", Title: "Find ROP Gadgets", Method: "findROPGadgets", ReadOnly: true,
		Params: []paramDef{
			{MCPName: "max_length", RPCName: "maxLength", Desc: "Maximum number of instructions per gadget (default: 5)", Type: paramNumber},
			{MCPName: "types", Desc: "Comma-separated gadget types to search for (e.g. 'ret,jmp,call')", Type: paramString},
		},
	},

	{Name: "detect_control_flow_flattening", Desc: "Detect control flow flattening obfuscation in a function. This obfuscation technique replaces normal control flow with a state machine/dispatcher pattern.", Title: "Detect CFF", Method: "detectControlFlowFlattening", ReadOnly: true,
		Params: []paramDef{{MCPName: "function_address", RPCName: "functionAddress", Desc: "Address of the function to analyze", Type: paramString, Required: true}},
	},

	// mark_code_coverage: JSON-parsed addresses + optional string
	{Name: "mark_code_coverage", Desc: "Mark a set of addresses as covered during dynamic analysis or fuzzing. Creates bookmarks at each address for visual tracking in Ghidra.", Title: "Mark Coverage", Method: "markCodeCoverage",
		Params: []paramDef{
			{MCPName: "addresses", Desc: "JSON array of address strings that were executed/covered", Type: paramJSONParse, Required: true},
			{MCPName: "bookmark_type", RPCName: "bookmarkType", Desc: "Bookmark type to use (default: 'Analysis')", Type: paramString},
		},
	},

	// =====================================================================
	// UTILITY TOOLS (60-62) + PING
	// =====================================================================

	// get_bookmarks: optional address filter
	{Name: "get_bookmarks", Desc: "Get all bookmarks at the given address, or all bookmarks in the program if no address is specified.", Title: "Get Bookmarks", Method: "getBookmarks", ReadOnly: true,
		Params: []paramDef{{MCPName: "address", Desc: "Optional address to filter bookmarks by", Type: paramString}},
	},

	{Name: "list_equates", Desc: "List all equates (named constants) defined in the program. Shows the name, value, and locations where each equate is applied.", Title: "List Equates", Method: "listEquates", ReadOnly: true},
	{Name: "ping", Desc: "Test connectivity to the Ghidra server. Returns 'pong' if the connection is alive. Use this to verify the bridge is working.", Title: "Ping", Method: "ping", ReadOnly: true},

	// =====================================================================
	// MULTI-INSTANCE TOOLS (63)
	// =====================================================================
	{Name: "list_ghidra_instances", Desc: "Scan for active GhidraMCP server instances on ports 8765-8774. Returns a list of reachable instances that can be targeted with the target_port parameter on other tools.", Title: "List Instances", ReadOnly: true,
		Custom: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			results := ghidraMultiClient.ScanPorts(8765, 8774)
			out, err := json.Marshal(results)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("marshal scan results: %v", err)), nil
			}
			return mcp.NewToolResultText(string(out)), nil
		},
	},

	// =====================================================================
	// STRUCT CRUD TOOLS (64-68)
	// =====================================================================
	{Name: "get_structure", Desc: "Get detailed information about a structure data type including all fields with their offsets, sizes, types, and comments.", Title: "Get Structure", Method: "getStructure", ReadOnly: true,
		Params: []paramDef{{MCPName: "name", Desc: "Name of the structure to inspect", Type: paramString, Required: true}},
	},
	{Name: "list_structures", Desc: "List all structure data types defined in the program with their names, sizes, and field counts. Supports pagination.", Title: "List Structures", Method: "listStructures", ReadOnly: true, Paginated: true},
	{Name: "edit_structure", Desc: "Edit a structure's fields using a list of operations. Each operation is a JSON object with 'action' (add/insert/delete/replace/clear) and relevant parameters like name, type, offset, size, comment, ordinal.", Title: "Edit Structure", Method: "editStructure",
		Params: []paramDef{
			{MCPName: "name", Desc: "Name of the structure to edit", Type: paramString, Required: true},
			{MCPName: "operations", Desc: `JSON array of edit operations, e.g. [{"action":"add","name":"field1","type":"int","size":4}]`, Type: paramJSONParse, Required: true},
		},
	},
	{Name: "rename_structure", Desc: "Rename an existing structure data type.", Title: "Rename Structure", Method: "renameStructure",
		Params: []paramDef{
			{MCPName: "current_name", RPCName: "currentName", Desc: "Current name of the structure", Type: paramString, Required: true},
			{MCPName: "new_name", RPCName: "newName", Desc: "New name for the structure", Type: paramString, Required: true},
		},
	},
	{Name: "delete_structure", Desc: "Delete a structure data type from the program's data type manager.", Title: "Delete Structure", Method: "deleteStructure",
		Params: []paramDef{{MCPName: "name", Desc: "Name of the structure to delete", Type: paramString, Required: true}},
	},

	// =====================================================================
	// ASYNC DECOMPILATION TOOLS (69-70)
	// =====================================================================
	{Name: "decompile_function_async", Desc: "Start an asynchronous decompilation of a function. Returns a task ID that can be polled with get_decompile_result. Useful for large functions that take a long time to decompile.", Title: "Async Decompile", Method: "decompileFunctionAsync", ReadOnly: true,
		Params: []paramDef{{MCPName: "address", Desc: "Address of the function to decompile (e.g. '0x00401000')", Type: paramString, Required: true}},
	},
	{Name: "get_decompile_result", Desc: "Poll for the result of an asynchronous decompilation task. Returns status ('pending', 'completed', or 'error') and the decompiled code when complete.", Title: "Get Decompile Result", Method: "getDecompileResult", ReadOnly: true,
		Params: []paramDef{{MCPName: "task_id", RPCName: "taskId", Desc: "Task ID returned by decompile_function_async", Type: paramString, Required: true}},
	},
}
