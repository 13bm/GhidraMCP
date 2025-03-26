# GhidraMCP

A Ghidra plugin that implements the Model Context Protocol (MCP) for AI-assisted binary analysis.

## Overview

GhidraMCP bridges the gap between Ghidra's powerful reverse engineering capabilities and AI assistants through the Model Context Protocol (MCP). This plugin enables AI models to connect to Ghidra and assist with binary analysis tasks, making reverse engineering more efficient and accessible.

## Features

- **AI-Powered Binary Analysis**: Connect AI assistants to Ghidra via the Model Context Protocol
- **Natural Language Interface**: Ask questions about binaries in plain English
- **Deep Code Insights**: Retrieve detailed function information and decompiled code
- **Binary Structure Analysis**: Explore imports, exports, and memory layouts
- **Automated Security Analysis**: Get AI-assisted insights about potential security vulnerabilities
- **Socket-Based Architecture**: High-performance communication between Ghidra and AI assistants
- **Cross-Platform Compatibility**: Works on all platforms supported by Ghidra

## Installation

### Prerequisites

- Ghidra 11.2.1+
- Java 17 or newer
- Python 3.8+ (for the bridge script)

### Steps

1. Download the latest release ZIP file from the [Releases](https://github.com/yourusername/GhidraMCP/releases) page
2. Open Ghidra
3. Navigate to `File > Install Extensions`
4. Click the "+" button and select the downloaded ZIP file
5. Restart Ghidra to complete the installation
6. Enable the extension by going to `File > Configure > Miscellaneous` and checking the box next to "MCPServerPlugin"

## Usage

### Starting the MCP Server

The server automatically starts when you open a Ghidra project after enabling the plugin. By default, it runs on:
- Host: `localhost`
- Port: `8765`

You can verify the server is running by checking the Ghidra console for messages like:
```
MCP Server started on port 8765
```

### Connecting with AI Assistants

#### Connecting with Claude

To connect Claude to the GhidraMCP plugin:

1. Install the MCP bridge script:
   ```bash
   pip install FastMCP
   ```

2. Add the following configuration to your Claude MCP setup:
   ```json
   {
     "mcpServers": {
       "ghidra": {
         "command": "python",
         "args": ["PATH-TO-REPO/GhidraMCP/ghidra_server.py"]
       }
     }
   }
   ```

The bridge script creates a connection between Ghidra and Claude, enabling real-time binary analysis through natural language.

### Available Tools

The plugin exposes several powerful functions through the MCP interface:

| Tool | Description |
|------|-------------|
| `get_function(address, decompile=False)` | Retrieve detailed information about a function at a specific address |
| `analyze_binary(question)` | Ask natural language questions about the loaded binary |
| `get_imports()` | List all imported functions in the binary |
| `get_exports()` | List all exported functions in the binary |
| `get_memory_map()` | Get the memory layout of the binary |
| `connect_to_ghidra(host, port)` | Connect to a specific Ghidra instance |
| `rename_function(current_name, new_name)` | Rename a function by its current name |
| `rename_data(address, new_name)` | Rename a data label at a specific address |
| `extract_api_call_sequences(address)` | Extract API calls from a function for security analysis |
| `identify_user_input_sources()` | Find potential sources of user input in the binary |
| `generate_call_graph(address, max_depth=3)` | Generate a hierarchical representation of function calls |
| `identify_crypto_patterns()` | Detect cryptographic implementations in the binary |
| `find_obfuscated_strings()` | Locate potentially obfuscated strings |

### Example Queries

Here are examples of questions you can ask through an MCP-compatible AI client:

- "What encryption algorithms are used in this binary?"
- "Can you show me the decompiled code for the function at 0x401000?"
- "What suspicious API calls does this malware make?"
- "Explain the purpose of this binary based on its imports and exports."
- "How does the authentication mechanism in this program work?"
- "Are there any potential buffer overflow vulnerabilities in this code?"
- "What network connections does this binary establish?"
- "Can you rename this function to something more descriptive?"
- "Show me all potential user input sources that could be exploited."
- "Generate a call graph for the main function."

## Advanced Usage

### Security Analysis Capabilities

GhidraMCP provides specialized tools for security-focused analysis:

#### API Call Sequence Analysis
Extract and categorize external API calls from a function for security analysis. This helps identify potentially dangerous functions and understand their interactions.

#### User Input Sources
Identify entry points where external data enters the program, crucial for vulnerability assessment and understanding attack surfaces.

#### Call Graph Generation
Create structured call graphs to understand execution flow, track data propagation, and identify potential attack paths.

#### Cryptographic Pattern Detection
Identify cryptographic implementations including standard algorithms (AES, RSA, etc.) and custom implementations based on code patterns.

#### Obfuscated String Detection
Find strings that may be obfuscated through techniques like XOR encoding or character-by-character construction.

### Custom Configurations

You can modify the server port by editing the `MCPServerPlugin.java` file:

```java
server.setPort(YOUR_CUSTOM_PORT);
```

### Integration with Analysis Workflows

GhidraMCP can be integrated into your existing analysis workflows:

1. Use Ghidra's standard analysis features to identify areas of interest
2. Leverage AI assistance through GhidraMCP for deeper understanding
3. Combine the AI insights with your manual analysis
4. Rename functions and data based on AI insights for better readability

## Building from Source

To build the plugin from source:

1. Clone this repository
   ```bash
   git clone https://github.com/yourusername/GhidraMCP.git
   ```

2. Set up a Ghidra development environment as described in the [Ghidra Developer Guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md)

3. Set the `GHIDRA_INSTALL_DIR` environment variable:
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

4. Build with Gradle:
   ```bash
   ./gradlew buildExtension
   ```

5. The extension ZIP will be created in the `dist` directory

## Troubleshooting

### Common Issues

- **Connection Issues**: Make sure the Ghidra instance is running and the plugin is enabled
- **Port Conflicts**: If port 8765 is already in use, modify the port in the plugin configuration
- **Bridge Script Errors**: Check if all required Python packages are installed with `pip install FastMCP`
- **Null Results for Analysis Functions**: Some security analysis functions may return null results if the binary doesn't contain relevant patterns

### Logs

Check the following logs for troubleshooting:
- Ghidra console for server-side messages
- `ghidra_mcp_bridge.log` for bridge script issues

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request


## Acknowledgments

- [National Security Agency (NSA)](https://github.com/NationalSecurityAgency/ghidra) for developing Ghidra
- [Model Context Protocol](https://modelcontextprotocol.io/) community
- All contributors to this project

---

*GhidraMCP is not affiliated with or endorsed by the NSA or the Ghidra project.*