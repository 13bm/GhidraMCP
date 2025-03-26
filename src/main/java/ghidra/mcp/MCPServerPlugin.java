package ghidra.mcp;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.plugin.PluginCategoryNames;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidraMCP",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Model Context Protocol Server for Ghidra",
    description = "Provides an MCP server for AI model integration with Ghidra"
)
public class MCPServerPlugin extends ProgramPlugin {
    private MCPServer server;

    public MCPServerPlugin(PluginTool tool) {
        super(tool);
    }
    
    public MCPServer getServer() {
        return server;
    }
    
    @Override
    public void init() {
        super.init();
        System.out.println("=========================================");
        System.out.println("MCP SERVER PLUGIN INITIALIZING");
        System.out.println("=========================================");
        try {
            server = new MCPServer(tool);
            System.out.println("MCP Server created successfully");
            server.setPort(8765);
            System.out.println("Starting MCP Server on port 8765...");
            server.startServer();
        } catch (Exception e) {
            System.out.println("Error starting MCP server: " + e.getMessage());
            e.printStackTrace();
        }
    }
}