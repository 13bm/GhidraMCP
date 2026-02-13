# GhidraMCP Tool Reference

Complete reference for all 69 MCP tools exposed by GhidraMCP. Each tool can be called by any MCP-compatible client (Claude Desktop, Claude Code, etc.).

## Global Parameters

Every tool (except `list_ghidra_instances`) accepts an optional **`target_port`** parameter:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target_port` | number | No | Port of a specific Ghidra instance (0 or omit for default). Use `list_ghidra_instances` to discover active instances. |

Tools marked **Paginated** accept two additional optional parameters:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip (default: 0) |
| `limit` | number | No | Maximum number of items to return |

---

## Table of Contents

- [Query Tools (1-21)](#query-tools)
- [Mutation Tools (22-38)](#mutation-tools)
- [Advanced Analysis Tools (39-45)](#advanced-analysis-tools)
- [Malware Analysis Tools (46-53)](#malware-analysis-tools)
- [IoT / Embedded Security Tools (54-59)](#iot--embedded-security-tools)
- [Utility Tools (60-62)](#utility-tools)
- [Multi-Instance Tools (63)](#multi-instance-tools)
- [Structure Management Tools (64-68)](#structure-management-tools)
- [Async Decompilation Tools (69-70)](#async-decompilation-tools)

---

## Query Tools

Read-only tools for inspecting the loaded binary. These never modify the program.

### `list_functions`

List all functions in the current program with their entry points, sizes, and return types.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

**Example:**
```json
{ "name": "list_functions", "arguments": { "offset": 0, "limit": 50 } }
```

---

### `list_classes`

List all classes and namespaces defined in the current program.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `list_imports`

List all imported symbols and functions from external libraries. Useful for understanding the binary's dependencies.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `list_exports`

List all exported symbols from the binary. These are the entry points available to other programs or libraries.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `list_namespaces`

List all namespaces in the program. Namespaces organize symbols into logical groups (classes, modules, etc.).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `list_data_items`

List all defined data items in the program (globals, constants, arrays, structs, etc.) with their addresses and types.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `list_strings`

List defined strings in the binary. Optionally filter by a case-insensitive substring match.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filter` | string | No | Case-insensitive substring filter on string content |
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

**Example:**
```json
{ "name": "list_strings", "arguments": { "filter": "password", "limit": 20 } }
```

---

### `search_functions_by_name`

Search for functions whose name contains the given query string. Useful for finding functions related to a specific feature or API.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | **Yes** | Substring to search for in function names |
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

**Example:**
```json
{ "name": "search_functions_by_name", "arguments": { "query": "malloc" } }
```

---

### `get_function_by_address`

Get detailed information about a function at the given address, including name, parameters, callers, and callees.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the function (e.g. `0x00401000`) |

**Example:**
```json
{ "name": "get_function_by_address", "arguments": { "address": "0x00401000" } }
```

---

### `get_current_address`

Get the address currently selected in Ghidra's listing view. Useful for understanding where the analyst is looking.

*No parameters (besides optional `target_port`).*

---

### `get_current_function`

Get information about the function that contains the currently selected address in Ghidra's listing view.

*No parameters (besides optional `target_port`).*

---

### `decompile_function`

Decompile a function by its name and return the C pseudocode. Useful for understanding what a named function does.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **Yes** | Name of the function to decompile |

**Example:**
```json
{ "name": "decompile_function", "arguments": { "name": "main" } }
```

---

### `decompile_function_by_address`

Decompile a function at the given address and return the C pseudocode.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the function to decompile (e.g. `0x00401000`) |

---

### `disassemble_function`

Get the assembly instructions for a function at the given address. Returns the raw disassembly listing.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the function to disassemble (e.g. `0x00401000`) |

---

### `get_xrefs_to`

Get all cross-references TO a given address. Shows what code references this location (callers, data readers, etc.).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Target address to find references to |
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `get_xrefs_from`

Get all cross-references FROM a given address. Shows what this location references (callees, data writes, etc.).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Source address to find references from |
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `get_function_xrefs`

Get all cross-references for a function by name, including both callers and callees.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **Yes** | Name of the function |
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `get_program_info`

Get metadata about the currently loaded program: name, architecture, compiler, executable format, creation date, and function count.

*No parameters (besides optional `target_port`).*

---

### `get_memory_map`

Get the full memory layout of the binary, including all segments with start/end addresses, sizes, and permission flags (RWX).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `get_variables`

Get all variables (parameters and locals) for a function at the given address, including names, types, storage locations, and stack offsets.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_address` | string | **Yes** | Address of the function |

---

## Mutation Tools

Tools that modify the program database. These create undo-able transactions in Ghidra.

### `rename_function`

Rename a function by its current name. Assigns a new user-defined name to make the function more readable.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `old_name` | string | **Yes** | Current name of the function |
| `new_name` | string | **Yes** | New name to assign to the function |

**Example:**
```json
{ "name": "rename_function", "arguments": { "old_name": "FUN_00401000", "new_name": "decrypt_config" } }
```

---

### `rename_function_by_address`

Rename a function by its address. Useful when the function has an auto-generated name like `FUN_00401000`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the function to rename |
| `new_name` | string | **Yes** | New name to assign to the function |

---

### `rename_data`

Rename a data label at the specified address. Assigns a meaningful name to a global variable, string, or constant.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the data item |
| `new_name` | string | **Yes** | New name to assign |

---

### `rename_variable`

Rename a local variable or parameter within a function to improve decompiler output readability.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_address` | string | **Yes** | Address of the function containing the variable |
| `old_name` | string | **Yes** | Current name of the variable |
| `new_name` | string | **Yes** | New name for the variable |

---

### `set_decompiler_comment`

Set a comment that appears in the decompiler view at the specified address.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address where the comment should appear |
| `comment` | string | **Yes** | Comment text to set |

---

### `set_disassembly_comment`

Set a comment that appears in the disassembly listing view at the specified address.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address where the comment should appear |
| `comment` | string | **Yes** | Comment text to set |

---

### `set_function_prototype`

Set the full function prototype (return type, name, and parameters) for a function.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_address` | string | **Yes** | Address of the function |
| `prototype` | string | **Yes** | Full C-style function prototype string |

**Example:**
```json
{
  "name": "set_function_prototype",
  "arguments": {
    "function_address": "0x00401000",
    "prototype": "int decrypt_buffer(char *buf, int len, char *key)"
  }
}
```

---

### `set_local_variable_type`

Change the data type of a local variable in a function. Improves decompiler output accuracy.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_address` | string | **Yes** | Address of the function containing the variable |
| `variable_name` | string | **Yes** | Name of the variable to retype |
| `new_type` | string | **Yes** | New data type (e.g. `int`, `char *`, `DWORD`) |

---

### `set_bookmark`

Set a bookmark at the given address. Bookmarks help track interesting locations for later review.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address to bookmark |
| `type` | string | **Yes** | Bookmark type (e.g. `Note`, `Warning`, `Error`, `Info`) |
| `category` | string | **Yes** | Category for the bookmark |
| `comment` | string | **Yes** | Descriptive comment for the bookmark |

---

### `remove_bookmark`

Remove a bookmark at the given address matching the specified type and category.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the bookmark to remove |
| `type` | string | **Yes** | Bookmark type to match |
| `category` | string | **Yes** | Bookmark category to match |

---

### `set_equate`

Set an equate (named constant) on a scalar operand at the given address. Replaces magic numbers with meaningful names.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the instruction containing the operand |
| `operand_index` | number | **Yes** | Index of the operand (0-based) |
| `name` | string | **Yes** | Name for the equate |
| `value` | number | **Yes** | Numeric value the equate represents |

**Example:**
```json
{
  "name": "set_equate",
  "arguments": {
    "address": "0x00401050",
    "operand_index": 1,
    "name": "PAGE_EXECUTE_READWRITE",
    "value": 64
  }
}
```

---

### `create_structure`

Create a new structure data type with the given name and fields.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **Yes** | Name for the new structure |
| `fields` | string (JSON) | **Yes** | JSON array of field definitions: `[{"name":"x","type":"int","size":4}]` |

**Example:**
```json
{
  "name": "create_structure",
  "arguments": {
    "name": "PacketHeader",
    "fields": "[{\"name\":\"magic\",\"type\":\"int\",\"size\":4},{\"name\":\"length\",\"type\":\"short\",\"size\":2},{\"name\":\"flags\",\"type\":\"byte\",\"size\":1}]"
  }
}
```

---

### `create_enum`

Create a new enum data type with the given name, size, and values.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **Yes** | Name for the new enum |
| `size` | number | **Yes** | Size of the enum in bytes (1, 2, 4, or 8). Default: 4 |
| `values` | string (JSON) | **Yes** | JSON object mapping enum member names to values: `{"OK":0,"ERROR":1}` |

**Example:**
```json
{
  "name": "create_enum",
  "arguments": {
    "name": "ErrorCode",
    "size": 4,
    "values": "{\"SUCCESS\":0,\"INVALID_PARAM\":1,\"OUT_OF_MEMORY\":2}"
  }
}
```

---

### `apply_data_type`

Apply a data type at the given address. Changes how Ghidra interprets the bytes at that location.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address where the type should be applied |
| `type_name` | string | **Yes** | Name of the data type to apply |

---

### `set_calling_convention`

Set the calling convention for a function.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_address` | string | **Yes** | Address of the function |
| `convention` | string | **Yes** | Calling convention name (e.g. `__stdcall`, `__cdecl`, `__fastcall`, `__thiscall`) |

---

### `set_image_base`

Set the image base address of the program. This rebases all addresses in the binary.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `new_base_address` | string | **Yes** | New base address for the image (e.g. `0x10000000`) |

---

### `set_memory_permissions`

Set the read/write/execute permission flags for a memory block at the given address.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Start address of the memory block |
| `read` | boolean | **Yes** | Whether the memory block is readable |
| `write` | boolean | **Yes** | Whether the memory block is writable |
| `execute` | boolean | **Yes** | Whether the memory block is executable |
| `is_volatile` | boolean | No | Whether the memory block is volatile (e.g. memory-mapped I/O) |

---

## Advanced Analysis Tools

Tools for deeper binary analysis, control flow, and vulnerability research.

### `patch_bytes`

Write raw bytes to the binary at the given address. The bytes are specified as a hex string.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address to patch |
| `hex_bytes` | string | **Yes** | Hex-encoded bytes to write (e.g. `90909090` for NOP sled) |

**Example:**
```json
{ "name": "patch_bytes", "arguments": { "address": "0x00401050", "hex_bytes": "9090" } }
```

---

### `get_basic_blocks`

Get all basic blocks for a function at the given address. Returns the control flow graph as a list of blocks with their start/end addresses and successors.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_address` | string | **Yes** | Address of the function to analyze |

---

### `extract_api_call_sequences`

Extract the sequence of external API calls made by a function, categorized by type (network, file, crypto, etc.) with security risk assessments.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the function to analyze |

---

### `identify_user_input_sources`

Identify all potential sources of user/external input in the binary (`scanf`, `recv`, `ReadFile`, etc.). Useful for finding attack surfaces.

*No parameters (besides optional `target_port`).*

---

### `generate_call_graph`

Generate a hierarchical call graph starting from a function, up to the specified depth. Includes complexity metrics for each node.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the starting function |
| `max_depth` | number | **Yes** | Maximum depth to traverse the call graph (default: 3) |

**Example:**
```json
{ "name": "generate_call_graph", "arguments": { "address": "0x00401000", "max_depth": 5 } }
```

---

### `identify_crypto_patterns`

Detect cryptographic implementations in the binary by analyzing function names, API usage, known constants (AES S-box, SHA-256 IVs), and code patterns.

*No parameters (besides optional `target_port`).*

---

### `find_obfuscated_strings`

Find strings that may be obfuscated, encoded, or constructed at runtime to evade static analysis. Detects XOR encoding, stack strings, and decryption routines.

*No parameters (besides optional `target_port`).*

---

## Malware Analysis Tools

Specialized tools for analyzing malicious binaries and indicators of compromise.

### `search_bytes`

Search for a byte pattern in the binary. Supports optional mask for wildcard bytes. Useful for finding signatures or shellcode.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | string | **Yes** | Hex byte pattern to search for (e.g. `4D5A9000`) |
| `mask` | string | No | Hex mask where `FF` = exact match, `00` = wildcard |
| `start_address` | string | No | Start address to begin search from |
| `max_results` | number | No | Maximum number of results to return |

**Example:**
```json
{
  "name": "search_bytes",
  "arguments": {
    "pattern": "4D5A9000",
    "mask": "FFFFFFFF",
    "max_results": 10
  }
}
```

---

### `emulate_function`

Emulate execution of a function from the given address with optional arguments. Returns register state and memory changes after execution.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the function to emulate |
| `args` | string (JSON) | No | JSON array of argument values to pass to the function |
| `max_steps` | number | No | Maximum number of instructions to emulate (default: 10000) |

**Example:**
```json
{
  "name": "emulate_function",
  "arguments": {
    "address": "0x00401200",
    "args": "[1, 2, 3]",
    "max_steps": 5000
  }
}
```

---

### `extract_iocs`

Extract Indicators of Compromise (IOCs) from the binary: URLs, IP addresses, domain names, file paths, registry keys, mutexes, and email addresses.

*No parameters (besides optional `target_port`).*

---

### `find_dynamic_api_resolution`

Find instances of dynamic API resolution (`LoadLibrary`/`GetProcAddress` patterns). Common in malware to hide imported functions from static analysis.

*No parameters (besides optional `target_port`).*

---

### `detect_anti_analysis`

Detect anti-debugging, anti-VM, and anti-analysis techniques in the binary. Identifies checks for debuggers, virtual machines, sandboxes, and timing attacks.

*No parameters (besides optional `target_port`).*

---

### `add_external_function`

Add an external function reference. Links an address in the binary to a known library function that was not automatically resolved.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `library` | string | **Yes** | Name of the external library (e.g. `kernel32.dll`) |
| `function_name` | string | **Yes** | Name of the external function |
| `address` | string | **Yes** | Address where the function is referenced |

---

### `get_pe_info`

Get PE (Portable Executable) header information for Windows binaries: DOS header, PE signature, sections, imports/exports, resources, and timestamps.

*No parameters (besides optional `target_port`).*

---

### `get_elf_info`

Get ELF (Executable and Linkable Format) header information for Linux/Unix binaries: program headers, section headers, symbol tables, and dynamic linking info.

*No parameters (besides optional `target_port`).*

---

## IoT / Embedded Security Tools

Tools for analyzing firmware, embedded systems, and binary exploitation potential.

### `create_memory_block`

Create a new memory block in the program. Useful for adding memory-mapped I/O regions or other memory areas in embedded firmware analysis.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **Yes** | Name for the memory block |
| `address` | string | **Yes** | Start address of the memory block |
| `size` | number | **Yes** | Size of the memory block in bytes |
| `permissions` | string | **Yes** | Permission string like `rwx`, `r-x`, `rw-` |
| `is_overlay` | boolean | No | Whether to create as an overlay block (default: false) |

**Example:**
```json
{
  "name": "create_memory_block",
  "arguments": {
    "name": "MMIO_UART",
    "address": "0x40000000",
    "size": 4096,
    "permissions": "rw-"
  }
}
```

---

### `detect_security_mitigations`

Detect security mitigations present in the binary: stack canaries, ASLR/PIE, DEP/NX, RELRO, SafeSEH, Control Flow Guard, and more.

*No parameters (besides optional `target_port`).*

---

### `find_format_string_vulns`

Find potential format string vulnerabilities by detecting calls to `printf`-family functions where the format argument may be user-controlled.

*No parameters (besides optional `target_port`).*

---

### `find_rop_gadgets`

Find Return-Oriented Programming (ROP) gadgets in the binary. Useful for exploit development and understanding binary exploitation potential.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `max_length` | number | No | Maximum number of instructions per gadget (default: 5) |
| `types` | string | No | Comma-separated gadget types to search for (e.g. `ret,jmp,call`) |

---

### `detect_control_flow_flattening`

Detect control flow flattening obfuscation in a function. This obfuscation technique replaces normal control flow with a state machine/dispatcher pattern.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `function_address` | string | **Yes** | Address of the function to analyze |

---

### `mark_code_coverage`

Mark a set of addresses as covered during dynamic analysis or fuzzing. Creates bookmarks at each address for visual tracking in Ghidra.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `addresses` | string (JSON) | **Yes** | JSON array of address strings that were executed/covered |
| `bookmark_type` | string | No | Bookmark type to use (default: `Analysis`) |

**Example:**
```json
{
  "name": "mark_code_coverage",
  "arguments": {
    "addresses": "[\"0x00401000\",\"0x00401020\",\"0x00401050\"]",
    "bookmark_type": "Coverage"
  }
}
```

---

## Utility Tools

General-purpose helpers for bookmarks, equates, and connectivity testing.

### `get_bookmarks`

Get all bookmarks at the given address, or all bookmarks in the program if no address is specified.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | No | Address to filter bookmarks by (omit for all) |

---

### `list_equates`

List all equates (named constants) defined in the program. Shows the name, value, and locations where each equate is applied.

*No parameters (besides optional `target_port`).*

---

### `ping`

Test connectivity to the Ghidra server. Returns `pong` if the connection is alive. Use this to verify the bridge is working.

*No parameters (besides optional `target_port`).*

---

## Multi-Instance Tools

Tools for working with multiple Ghidra windows simultaneously.

### `list_ghidra_instances`

Scan for active GhidraMCP server instances on ports 8765-8774. Returns a list of reachable instances that can be targeted with the `target_port` parameter on other tools.

*No parameters.* This is the only tool that does not accept `target_port`.

**Example response:**
```json
[
  { "port": 8765, "status": "active", "program": "malware.exe" },
  { "port": 8766, "status": "active", "program": "firmware.bin" }
]
```

---

## Structure Management Tools

Full CRUD operations for Ghidra structure data types. Essential for reverse-engineering complex data layouts.

### `get_structure`

Get detailed information about a structure data type including all fields with their offsets, sizes, types, and comments.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **Yes** | Name of the structure to inspect |

**Example:**
```json
{ "name": "get_structure", "arguments": { "name": "PacketHeader" } }
```

---

### `list_structures`

List all structure data types defined in the program with their names, sizes, and field counts.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `offset` | number | No | Number of items to skip for pagination |
| `limit` | number | No | Maximum number of items to return |

---

### `edit_structure`

Edit a structure's fields using a list of operations. Supports adding, inserting, deleting, replacing, and clearing fields.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **Yes** | Name of the structure to edit |
| `operations` | string (JSON) | **Yes** | JSON array of edit operations (see below) |

**Operation actions:**

| Action | Required Fields | Description |
|--------|----------------|-------------|
| `add` | `name`, `type`, `size` | Append a field to the end of the structure |
| `insert` | `offset`, `name`, `type`, `size` | Insert a field at a specific byte offset |
| `delete` | `offset`, `size` | Delete bytes at a specific offset |
| `replace` | `offset`, `name`, `type`, `size` | Replace bytes at an offset with a new field |
| `clear` | `ordinal` | Clear a field by its ordinal (0-based index) |

Optional field: `comment` (string) -- adds a comment to the field.

**Example:**
```json
{
  "name": "edit_structure",
  "arguments": {
    "name": "PacketHeader",
    "operations": "[{\"action\":\"add\",\"name\":\"checksum\",\"type\":\"uint\",\"size\":4,\"comment\":\"CRC32 checksum\"}]"
  }
}
```

---

### `rename_structure`

Rename an existing structure data type.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `current_name` | string | **Yes** | Current name of the structure |
| `new_name` | string | **Yes** | New name for the structure |

---

### `delete_structure`

Delete a structure data type from the program's data type manager.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **Yes** | Name of the structure to delete |

---

## Async Decompilation Tools

Non-blocking decompilation for large functions that may take 30+ seconds. Start a decompilation, continue other work, then poll for the result.

### `decompile_function_async`

Start an asynchronous decompilation of a function. Returns a task ID immediately.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | **Yes** | Address of the function to decompile (e.g. `0x00401000`) |

**Example response:**
```json
{ "taskId": "a1b2c3d4-...", "status": "submitted", "functionName": "FUN_00401000", "address": "0x00401000" }
```

---

### `get_decompile_result`

Poll for the result of an asynchronous decompilation task.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | string | **Yes** | Task ID returned by `decompile_function_async` |

**Status values:**

| Status | Description |
|--------|-------------|
| `pending` | Decompilation is still running |
| `completed` | Done -- `result` field contains the C pseudocode |
| `error` | Failed -- `error` field contains the error message |

**Example workflow:**
```json
// Step 1: Start async decompilation
{ "name": "decompile_function_async", "arguments": { "address": "0x00401000" } }
// Response: { "taskId": "abc-123", "status": "submitted" }

// Step 2: Poll for result (repeat until status != "pending")
{ "name": "get_decompile_result", "arguments": { "task_id": "abc-123" } }
// Response: { "status": "completed", "result": "int main(int argc, char **argv) { ... }" }
```
