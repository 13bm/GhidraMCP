# GhidraMCP
[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/13bm/GhidraMCP)](https://archestra.ai/mcp-catalog/13bm__ghidramcp)

[![Build](https://github.com/13bm/GhidraMCP/actions/workflows/build.yml/badge.svg)](https://github.com/13bm/GhidraMCP/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A Ghidra extension that exposes 69 reverse-engineering tools to AI assistants through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). Open a binary in Ghidra, enable the plugin, and let Claude (or any MCP client) decompile functions, rename symbols, annotate code, search for vulnerabilities, and more.

## Architecture

```
 AI Client (Claude Desktop / CLI)
        |  stdio + MCP JSON-RPC
        v
   Go MCP Bridge  (mcp_bridge)
        |  TCP, length-prefixed JSON-RPC
        v
   Ghidra Plugin  (MCPServerPlugin)
        |
        v
   Ghidra Program API
```

The **Ghidra plugin** (Java) starts a TCP server inside Ghidra and auto-launches the **Go bridge** binary. The bridge speaks MCP over stdio to the AI client and forwards calls to the Java plugin over a local TCP socket with 4-byte length-prefixed JSON-RPC framing. Optional API-key authentication protects the TCP channel.

## Features

- **69 MCP tools** spanning query, mutation, analysis, malware triage, IoT/embedded security, structure management, async decompilation, and multi-instance support
- **Easy setup** -- plugin auto-starts the bridge; use **MCP > Settings > Write to Claude Config** to configure your MCP client
- **Cross-platform** -- prebuilt bridge binaries for Linux x86_64, Windows x86_64, macOS x86_64 and macOS ARM64
- **Configurable** -- port, localhost-only binding, API-key auth, auto-start, bridge enable/disable via `GhidraMCP.properties`
- **Multi-instance** -- work with multiple Ghidra windows simultaneously using `target_port` to route tool calls
- **Async decompilation** -- decompile large functions without blocking; poll for results later
- **Connection retry** -- the bridge reconnects automatically if Ghidra restarts or the connection drops
- **Pagination** -- large result sets (functions, strings, imports, ...) support `offset`/`limit` for safe incremental retrieval
- **CI/CD** -- automated builds, Go + Java tests, Ghidra integration tests, and auto-release when a new Ghidra version drops

## Quick Start

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) 12.0.3+
- Java 21+
- An MCP-compatible AI client ([Claude Desktop](https://claude.ai/download), [Claude Code](https://docs.anthropic.com/en/docs/claude-code), etc.)

### Install

1. Download the latest release ZIP from [Releases](https://github.com/13bm/GhidraMCP/releases)
2. In Ghidra: **File > Install Extensions > "+" > select the ZIP**
3. Restart Ghidra

### Enable

1. Open a project and a program (binary)
2. **File > Configure > Miscellaneous** -- check **MCPServerPlugin**
3. The plugin auto-starts the TCP server (default `localhost:8765`) and launches the bridge

To configure Claude Desktop, open **MCP > Settings** and click **Write to Claude Config**. For other MCP clients, click **Copy to Clipboard** and add this to your client config:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/mcp_bridge",
      "args": ["--host", "localhost", "--port", "8765"]
    }
  }
}
```

If you have an API key set, include it in the `env` block (the plugin does this automatically):

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/mcp_bridge",
      "args": ["--host", "localhost", "--port", "8765"],
      "env": {
        "GHIDRA_API_KEY": "your-key-here"
      }
    }
  }
}
```

You can also grab the snippet from Ghidra: **MCP > Copy MCP Config** (copies it to your clipboard).

## Tools

> **Full reference with parameters, types, and examples:** **[TOOLS.md](TOOLS.md)**

The tables below give a quick overview. See [TOOLS.md](TOOLS.md) for detailed parameter docs.

### Query (1-21)

| Tool | Description |
|------|-------------|
| `list_functions` | List all functions with entry points, sizes, return types |
| `list_classes` | List all classes / namespaces |
| `list_imports` | List imported symbols and external dependencies |
| `list_exports` | List exported symbols |
| `list_namespaces` | List all namespaces |
| `list_data_items` | List defined data (globals, constants, arrays, structs) |
| `list_strings` | List strings with optional substring filter |
| `search_functions_by_name` | Search functions by name substring |
| `get_function_by_address` | Detailed info for a function at an address |
| `get_current_address` | Address currently selected in Ghidra |
| `get_current_function` | Function at the current cursor position |
| `decompile_function` | Decompile by name to C pseudocode |
| `decompile_function_by_address` | Decompile by address to C pseudocode |
| `disassemble_function` | Raw disassembly listing for a function |
| `get_xrefs_to` | Cross-references TO an address |
| `get_xrefs_from` | Cross-references FROM an address |
| `get_function_xrefs` | All xrefs (callers + callees) for a function |
| `get_program_info` | Program metadata (arch, compiler, format, etc.) |
| `get_memory_map` | Memory layout with segment permissions |
| `get_variables` | Parameters and locals for a function |

### Mutation (22-38)

| Tool | Description |
|------|-------------|
| `rename_function` | Rename a function by name |
| `rename_function_by_address` | Rename a function by address |
| `rename_data` | Rename a data label |
| `rename_variable` | Rename a local variable |
| `set_decompiler_comment` | Set a decompiler-view comment |
| `set_disassembly_comment` | Set a disassembly-view comment |
| `set_function_prototype` | Set full function prototype |
| `set_local_variable_type` | Change a variable's data type |
| `set_bookmark` | Add a bookmark |
| `remove_bookmark` | Remove a bookmark |
| `set_equate` | Set a named constant on a scalar operand |
| `create_structure` | Create a structure data type |
| `create_enum` | Create an enum data type |
| `apply_data_type` | Apply a data type at an address |
| `set_calling_convention` | Set calling convention for a function |
| `set_image_base` | Set the image base address |
| `set_memory_permissions` | Modify memory block permissions |

### Advanced Analysis (39-45)

| Tool | Description |
|------|-------------|
| `patch_bytes` | Patch raw bytes at an address |
| `get_basic_blocks` | Get basic blocks for a function |
| `extract_api_call_sequences` | Extract API call sequences for security analysis |
| `identify_user_input_sources` | Find user-input entry points |
| `generate_call_graph` | Hierarchical call graph |
| `identify_crypto_patterns` | Detect crypto implementations |
| `find_obfuscated_strings` | Locate obfuscated strings |

### Malware Analysis (46-53)

| Tool | Description |
|------|-------------|
| `search_bytes` | Search for byte patterns |
| `emulate_function` | Emulate a function |
| `extract_iocs` | Extract indicators of compromise |
| `find_dynamic_api_resolution` | Detect dynamic API resolution |
| `detect_anti_analysis` | Detect anti-analysis techniques |
| `add_external_function` | Add an external function reference |
| `get_pe_info` | PE header details |
| `get_elf_info` | ELF header details |

### IoT / Embedded Security (54-59)

| Tool | Description |
|------|-------------|
| `create_memory_block` | Create a memory block |
| `detect_security_mitigations` | Detect binary security mitigations |
| `find_format_string_vulns` | Find format-string vulnerabilities |
| `find_rop_gadgets` | Find ROP gadgets |
| `detect_control_flow_flattening` | Detect control-flow flattening |
| `mark_code_coverage` | Mark code coverage regions |

### Utility (60-62)

| Tool | Description |
|------|-------------|
| `get_bookmarks` | List bookmarks (optionally by address) |
| `list_equates` | List all equates |
| `ping` | Health-check the connection |

### Multi-Instance (63)

| Tool | Description |
|------|-------------|
| `list_ghidra_instances` | Scan ports 8765-8774 for running Ghidra instances |

All tools accept an optional `target_port` parameter to route calls to a specific Ghidra instance. This lets you work with multiple binaries open in separate Ghidra windows simultaneously.

### Structure Management (64-68)

| Tool | Description |
|------|-------------|
| `get_structure` | Get full details of a structure (fields, offsets, types) |
| `list_structures` | List all defined structures with pagination |
| `edit_structure` | Add, insert, delete, replace, or clear fields in a structure |
| `rename_structure` | Rename an existing structure |
| `delete_structure` | Delete a structure data type |

### Async Decompilation (69-70)

| Tool | Description |
|------|-------------|
| `decompile_function_async` | Start async decompilation of a large function (returns task ID) |
| `get_decompile_result` | Poll for an async decompilation result by task ID |

Async decompilation is useful for large functions that may take 30+ seconds to decompile. The client can start the decompilation, continue other work, and poll for the result later.

## Configuration

The plugin stores settings in `GhidraMCP.properties` inside Ghidra's user settings directory:

| Property | Default | Description |
|----------|---------|-------------|
| `port` | `8765` | TCP port for the Java server |
| `localhost_only` | `true` | Bind to localhost only |
| `api_key` | *(empty)* | Shared secret for bridge authentication |
| `auto_start` | `true` | Start the server when the plugin loads |
| `bridge_enabled` | `true` | Auto-launch the Go bridge binary |

### Settings Dialog

Open **MCP > Settings** in the Ghidra menu to configure all properties through a GUI. The dialog includes:

- Editable fields for port, localhost binding, API key, auto-start, and bridge enabled
- **Generate** button to create a cryptographically random 32-character API key
- **Write to Claude Config** button to merge GhidraMCP into Claude Desktop's `claude_desktop_config.json`
- **Copy to Clipboard** button to copy the MCP config JSON snippet for manual setup
- Security warning if you enable remote access without an API key
- Auto-restart prompt if the server is running when you save

Changes are saved to disk when you click OK. You can also edit the properties file directly at the path shown in the dialog.

If `auto_start` is `false`, start the server manually from **MCP > Toggle Server** in the Ghidra menu.

> **Note:** The `bridge_enabled` setting is for advanced use cases — developers debugging the bridge binary or users with a custom MCP client that talks TCP directly to the Java server. Most users should leave it enabled.

## Security

By default the TCP server binds to **localhost only** and has **no API key**, which is fine for local single-user use. For stricter setups:

### API-Key Authentication

1. Open **MCP > Settings** and click **Generate** to create a random key (or type your own)
2. Click OK to save — the bridge picks up the key automatically on next start
3. On connect, the bridge sends an `authenticate` request with the key before any other calls
4. The server rejects all non-auth requests until authentication succeeds
5. After **3 failed attempts** the server terminates the connection

The API key is passed to the bridge via the `GHIDRA_API_KEY` environment variable (not as a CLI flag) to prevent leaking it in the process argument list. When running the bridge manually, set the environment variable:

```bash
# Linux/macOS
export GHIDRA_API_KEY="your-key-here"
./mcp_bridge --host localhost --port 8765

# Windows (PowerShell)
$env:GHIDRA_API_KEY = "your-key-here"
.\mcp_bridge.exe --host localhost --port 8765
```

When an API key is set, the **Write to Claude Config** and **Copy to Clipboard** buttons in the Settings dialog include the key in the `env` block automatically.

### Localhost Binding

With `localhost_only=true` (default), the server only accepts connections from `127.0.0.1`. Set to `false` if you need remote access (e.g., Ghidra on a headless server), but **always use an API key** when exposing the port beyond localhost.

### Remote / Headless Setup

GhidraMCP can serve AI clients running on a different machine. This is useful when Ghidra runs on a headless analysis server while the AI client runs elsewhere.

1. Open **MCP > Settings**
2. Uncheck **Localhost Only** to accept remote connections
3. Click **Generate** to create an API key (always use one for remote access)
4. Click OK and restart the server

On the remote machine, configure the MCP client to point at the Ghidra host:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/mcp_bridge",
      "args": ["--host", "ghidra-server.local", "--port", "8765"],
      "env": {
        "GHIDRA_API_KEY": "your-key-here"
      }
    }
  }
}
```

> **Warning:** Always use an API key when exposing the server beyond localhost. Without authentication, anyone who can reach the port has full access to the Ghidra API.

## Building from Source

```bash
git clone https://github.com/13bm/GhidraMCP.git
cd GhidraMCP
```

### Build the Go bridge

```bash
cd mcp-bridge
go build -o mcp_bridge .
cd ..
```

### Build the Ghidra extension

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle buildExtension
```

The extension ZIP will be in `dist/`.

### Run tests

```bash
# Go tests
cd mcp-bridge && go test ./... -v && cd ..

# Java unit + integration tests (requires Xvfb on headless Linux)
xvfb-run gradle test -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR
```

## CI/CD

The project uses GitHub Actions for automated builds and releases:

- **`build.yml`** -- Triggered on push/PR to `master` and on tags. Runs Go tests, cross-compiles the bridge for 4 platforms, runs Java unit + Ghidra integration tests under Xvfb, builds the extension ZIP, and creates GitHub Releases on `v*` tags.
- **`check-ghidra-release.yml`** -- Runs daily. Detects new Ghidra releases, opens a version-bump PR, auto-approves via GitHub App, and auto-merges if all tests pass.

## Contributing

Contributions welcome! Please open issues or submit pull requests.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes
4. Push and open a Pull Request

## License

[Apache License 2.0](LICENSE)

## Acknowledgments

- [NSA / Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [mcp-go](https://github.com/mark3labs/mcp-go) -- Go MCP SDK

---

*GhidraMCP is not affiliated with or endorsed by the NSA or the Ghidra project.*
