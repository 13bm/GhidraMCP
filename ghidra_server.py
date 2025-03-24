import os
import json
import time
import logging
import socket
import sys
from threading import Thread

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("ghidra_mcp_bridge.log"), logging.StreamHandler()]
)
logger = logging.getLogger("GhidraMCPBridge")

# Import the MCP SDK
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent, Tool, Resource

# Ghidra MCP Socket Client
class GhidraMCPSocketClient:
    """Client for the Model Context Protocol server in Ghidra"""
    
    def __init__(self, host='localhost', port=8765):
        self.host = host
        self.port = port
        self.socket = None
        self.id_counter = 0
        
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            logger.info(f"Connected to Ghidra MCP server at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Ghidra MCP server: {str(e)}")
            return False
        
    def disconnect(self):
        if self.socket:
            self.socket.close()
            self.socket = None
            
    def is_connected(self):
        return self.socket is not None
            
    def send_request(self, method, params=None):
        if not self.socket:
            raise Exception("Not connected to Ghidra MCP server")
            
        self.id_counter += 1
        request = {
            "id": str(self.id_counter),
            "method": method
        }
        
        if params:
            request["params"] = params
            
        request_str = json.dumps(request) + "\n"
        self.socket.sendall(request_str.encode())
        
        # Read response
        response_data = b""
        while True:
            chunk = self.socket.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if response_data.endswith(b"\n"):
                break
        
        response_str = response_data.decode()
        response = json.loads(response_str)
        
        if "error" in response:
            logger.warning(f"Error in Ghidra MCP response: {response['error']}")
        
        return response.get("result")
        
    def get_context(self):
        return self.send_request("getContext")
        
    def get_function(self, address):
        return self.send_request("getFunctionAt", {"address": address})
        
    def get_decompiled_code(self, address):
        return self.send_request("getDecompiledCode", {"address": address})
    
    def analyze_binary_for_question(self, question):
        return self.send_request("analyzeBinaryForQuestion", {"question": question})
        
    def get_all_functions(self):
        return self.send_request("getAllFunctions")
    
    def get_strings(self):
        return self.send_request("getStrings")
    
    def get_imports(self):
        return self.send_request("getImports")
    
    def get_exports(self):
        return self.send_request("getExports")
    
    def get_memory_map(self):
        return self.send_request("getMemoryMap")

# Create the Ghidra bridge client instance
ghidra_client = GhidraMCPSocketClient()

# Create an MCP FastMCP instance that Claude will connect to
mcp = FastMCP("Ghidra MCP Bridge")

# Define resources
@mcp.resource("http://localhost/query", name="get_program_info")
async def get_context_resource():
    """Get basic information about the current program loaded in Ghidra"""
    try:
        if not ghidra_client.is_connected():
            if not ensure_connection():
                return {"success": False, "error": "Failed to connect to Ghidra"}
            
        context = ghidra_client.get_context()
        return {"success": True, "context": context}
    except Exception as e:
        logger.error(f"Error getting context: {str(e)}")
        return {"success": False, "error": str(e)}

@mcp.resource("http://localhost/functions", name="list_functions")
async def get_all_functions_resource():
    """Get a list of all functions in the binary that Ghidra has identified"""
    try:
        if not ghidra_client.is_connected():
            if not ensure_connection():
                return {"success": False, "error": "Failed to connect to Ghidra"}
            
        functions = ghidra_client.get_all_functions()
        return {"success": True, "functions": functions}
    except Exception as e:
        logger.error(f"Error getting functions: {str(e)}")
        return {"success": False, "error": str(e)}

@mcp.resource("http://localhost/strings", name="list_strings")
async def get_strings_resource():
    """Get a list of all strings found in the binary by Ghidra"""
    try:
        if not ghidra_client.is_connected():
            if not ensure_connection():
                return {"success": False, "error": "Failed to connect to Ghidra"}
            
        strings = ghidra_client.get_strings()
        return {"success": True, "strings": strings}
    except Exception as e:
        logger.error(f"Error getting strings: {str(e)}")
        return {"success": False, "error": str(e)}

# Define tools
@mcp.tool(name="get_function")
async def get_function_tool(address: str, decompile: bool = False):
    """
    Get detailed information about a function at a specific address
    
    This tool provides details about a specific function in the binary, including its signature,
    parameters, local variables, and optionally the decompiled code.
    
    Args:
        address: The address of the function to analyze (e.g., "0x401000")
        decompile: Whether to include decompiled source code (default: False)
    """
    try:
        if not ghidra_client.is_connected():
            if not ensure_connection():
                return [TextContent(type="text", text=json.dumps({"success": False, "error": "Failed to connect to Ghidra"}))]
            
        function_info = ghidra_client.get_function(address)
        
        if decompile:
            decompiled = ghidra_client.get_decompiled_code(address)
            result = {"success": True, "function": function_info, "decompiled": decompiled}
        else:
            result = {"success": True, "function": function_info}
            
        return [TextContent(type="text", text=json.dumps(result))]
    except Exception as e:
        logger.error(f"Error getting function: {str(e)}")
        return [TextContent(type="text", text=json.dumps({"success": False, "error": str(e)}))]

@mcp.tool(name="analyze_binary")
async def analyze_binary_tool(question: str):
    """
    Analyze the loaded binary in Ghidra based on a natural language question
    
    This tool allows you to ask questions about the binary and get analysis results.
    Examples of questions you can ask:
    - What encryption algorithms are used in this binary?
    - Are there any suspicious API calls?
    - How does the authentication logic work?
    - What network connections does this binary make?
    
    Args:
        question: The natural language question about the binary
    """
    try:
        if not ghidra_client.is_connected():
            if not ensure_connection():
                return [TextContent(type="text", text=json.dumps({"success": False, "error": "Failed to connect to Ghidra"}))]
            
        if not question:
            return [TextContent(type="text", text=json.dumps({"success": False, "error": "Missing question"}))]
            
        analysis = ghidra_client.analyze_binary_for_question(question)
        return [TextContent(type="text", text=json.dumps({"success": True, "analysis": analysis}))]
    except Exception as e:
        logger.error(f"Error analyzing binary: {str(e)}")
        return [TextContent(type="text", text=json.dumps({"success": False, "error": str(e)}))]

@mcp.tool(name="connect_to_ghidra")
async def connect_tool(host: str = "localhost", port: int = 8765):
    """
    Connect to the Ghidra MCP server
    
    Use this tool to connect to a Ghidra instance running with the MCP plugin.
    The default host is localhost and the default port is 8765.
    
    Args:
        host: The hostname or IP address of the Ghidra server (default: "localhost")
        port: The port number of the Ghidra server (default: 8765)
    """
    try:
        # Update client settings
        ghidra_client.host = host
        ghidra_client.port = port
        
        # Disconnect if already connected
        if ghidra_client.is_connected():
            ghidra_client.disconnect()
            
        # Connect to Ghidra MCP server
        success = ghidra_client.connect()
        
        if success:
            result = {"success": True, "message": f"Connected to Ghidra MCP server at {host}:{port}"}
        else:
            result = {"success": False, "error": f"Failed to connect to Ghidra MCP server at {host}:{port}"}
            
        return [TextContent(type="text", text=json.dumps(result))]
    except Exception as e:
        logger.error(f"Error connecting to Ghidra: {str(e)}")
        return [TextContent(type="text", text=json.dumps({"success": False, "error": str(e)}))]

@mcp.tool(name="get_imports")
async def get_imports_tool():
    """
    Get a list of all imported functions in the binary
    
    This tool returns all external library functions that the binary imports,
    which is useful for understanding the binary's dependencies and functionality.
    """
    try:
        if not ghidra_client.is_connected():
            if not ensure_connection():
                return [TextContent(type="text", text=json.dumps({"success": False, "error": "Failed to connect to Ghidra"}))]
            
        imports = ghidra_client.get_imports()
        return [TextContent(type="text", text=json.dumps({"success": True, "imports": imports}))]
    except Exception as e:
        logger.error(f"Error getting imports: {str(e)}")
        return [TextContent(type="text", text=json.dumps({"success": False, "error": str(e)}))]

@mcp.tool(name="get_exports")
async def get_exports_tool():
    """
    Get a list of all exported functions in the binary
    
    This tool returns all functions that the binary exports for other programs to use,
    which is useful for understanding the binary's API or library functionality.
    """
    try:
        if not ghidra_client.is_connected():
            if not ensure_connection():
                return [TextContent(type="text", text=json.dumps({"success": False, "error": "Failed to connect to Ghidra"}))]
            
        exports = ghidra_client.get_exports()
        return [TextContent(type="text", text=json.dumps({"success": True, "exports": exports}))]
    except Exception as e:
        logger.error(f"Error getting exports: {str(e)}")
        return [TextContent(type="text", text=json.dumps({"success": False, "error": str(e)}))]

@mcp.tool(name="get_memory_map")
async def get_memory_map_tool():
    """
    Get the memory layout of the binary
    
    This tool returns information about how the binary is mapped into memory,
    including code sections, data sections, and their addresses.
    """
    try:
        if not ghidra_client.is_connected():
            if not ensure_connection():
                return [TextContent(type="text", text=json.dumps({"success": False, "error": "Failed to connect to Ghidra"}))]
            
        memory_map = ghidra_client.get_memory_map()
        return [TextContent(type="text", text=json.dumps({"success": True, "memory_map": memory_map}))]
    except Exception as e:
        logger.error(f"Error getting memory map: {str(e)}")
        return [TextContent(type="text", text=json.dumps({"success": False, "error": str(e)}))]

def ensure_connection():
    """Ensure we're connected to the Ghidra MCP server"""
    if not ghidra_client.is_connected():
        max_attempts = 3
        for attempt in range(max_attempts):
            if ghidra_client.connect():
                logger.info(f"Connected to Ghidra MCP server")
                return True
            else:
                logger.warning(f"Could not connect to Ghidra MCP server (attempt {attempt+1}/{max_attempts})")
                if attempt < max_attempts - 1:
                    logger.info("Retrying in 2 seconds...")
                    time.sleep(2)
        
        logger.error("Failed to connect to Ghidra MCP server after multiple attempts")
        return False
    
    return True

# Connect to Ghidra MCP server on startup
try:
    ghidra_client.connect()
except Exception as e:
    logger.warning(f"Initial connection to Ghidra MCP server failed: {str(e)}")
    logger.warning("The bridge will still start and can be connected later")

if __name__ == "__main__":
    print("Starting Ghidra MCP Bridge...", file=sys.stderr)
    
    # List all registered tools and resources for debugging
    try:
        resource_routes = dir(mcp._server.resources)
        tool_names = [tool.name for tool in mcp._server.tools]
        print(f"Registered resources: {resource_routes}", file=sys.stderr)
        print(f"Registered tools: {tool_names}", file=sys.stderr)
    except Exception as e:
        print(f"Error listing resources and tools: {str(e)}", file=sys.stderr)
    
    # Run the server
    mcp.run()