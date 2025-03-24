The server automatically starts when you open a Ghidra project after enabling the plugin. You can connect any MCP-compatible AI client to this address.# GhidraMCP

A Ghidra plugin that implements the Model Context Protocol (MCP) for AI-assisted binary analysis.

## Overview

GhidraMCP bridges the gap between Ghidra's powerful reverse engineering capabilities and AI assistants through the Model Context Protocol (MCP). This plugin allows AI models to connect to Ghidra and assist with binary analysis tasks.

## Features

- Connect AI assistants to Ghidra via the Model Context Protocol
- Analyze binaries using natural language queries
- Retrieve function information and decompiled code
- Explore imports, exports, and memory layouts
- Get AI-assisted insights about binary behaviors and patterns

## Installation

1. Download the latest release ZIP file
2. Open Ghidra
3. Navigate to File > Install Extensions
4. Click the "+" button and select the downloaded ZIP file
5. Restart Ghidra to complete the installation
6. Enable the extension by going to File > Configure > Miscellaneous and checking the box next to "MCPServerPlugin"

## Usage

### Connecting to the MCP Server

Once enabled, the plugin starts an MCP server with the following default configuration:
- Host: localhost
- Port: 8765

### Connecting with Claude

To connect Claude to the GhidraMCP plugin, you'll need to configure the MCP server settings and start the bridge script. 

1. Add the following configuration to your Claude MCP setup:

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

2. Replace `PATH-TO-REPO` with the actual path to your GhidraMCP repository on your system.

3. Start the bridge script by running the `ghidra_server.py` Python script:
   ```
   python PATH-TO-REPO/GhidraMCP/ghidra_server.py
   ```

This script must be running to bridge the connection between Ghidra and Claude desktop. It acts as an intermediary that allows Claude to communicate with Ghidra through the MCP protocol.

### Available Tools

The plugin exposes several functions through the MCP interface:

- `get_function(address, decompile=False)`: Retrieve information about a function at a specific address
- `analyze_binary(question)`: Ask natural language questions about the loaded binary
- `get_imports()`: List all imported functions in the binary
- `get_exports()`: List all exported functions in the binary
- `get_memory_map()`: Get the memory layout of the binary

### Example Queries

Here are examples of questions you can ask through an MCP-compatible AI client:

```
What encryption algorithms are used in this binary?
Can you show me the decompiled code for the function at 0x401000?
What suspicious API calls does this malware make?
Explain the purpose of this binary based on its imports and exports.
How does the authentication mechanism in this program work?
```

## Building from Source

To build the plugin from source:

1. Clone this repository
2. Set up a Ghidra development environment as described in the [Ghidra Developer Guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md)
3. Build with Gradle: `gradle buildExtension`
4. The extension ZIP will be created in the `dist` directory

## Development

This is an early-stage project intended to demonstrate the potential of combining AI capabilities with Ghidra through the Model Context Protocol. Contributions are welcome!

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

See the LICENSE file for details about the project's license.

## Acknowledgments

- [National Security Agency (NSA)](https://github.com/NationalSecurityAgency/ghidra) for developing Ghidra
- [Model Context Protocol](https://modelcontextprotocol.io/) community
- All contributors to this project
