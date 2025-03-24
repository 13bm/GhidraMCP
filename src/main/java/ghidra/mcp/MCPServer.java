package ghidra.mcp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidraMCP",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Model Context Protocol Server",
    description = "Provides an MCP server for AI model integration with Ghidra"
)
//@formatter:on
public class MCPServer extends ProgramPlugin {
    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private boolean running = false;
    private int port = 8765;
    private MCPContextProvider contextProvider;

    public MCPServer(PluginTool tool) {
        super(tool);
        contextProvider = new MCPContextProvider();
    }

    @Override
    public void init() {
        super.init();
    }
    
    public void startServer() {
        if (running) {
            System.out.println("MCP Server already running");
            return;
        }
        
        try {
            System.out.println("MCP Server binding to port " + port);
            serverSocket = new ServerSocket(port);
            threadPool = Executors.newCachedThreadPool();
            running = true;
            
            System.out.println("MCP Server socket created successfully");
            
            // Start a thread to listen for connections
            new Thread(() -> {
                System.out.println("MCP Server listener thread started");
                while (running) {
                    try {
                        System.out.println("MCP Server waiting for connections on port " + port);
                        Socket clientSocket = serverSocket.accept();
                        System.out.println("MCP Server: Client connected from " + clientSocket.getInetAddress());
                        MCPClientHandler handler = new MCPClientHandler(clientSocket, contextProvider);
                        threadPool.submit(handler);
                    } catch (IOException e) {
                        if (running) {
                            System.out.println("MCP Server socket error: " + e.getMessage());
                            e.printStackTrace();
                        }
                    }
                }
            }).start();
            
            System.out.println("MCP Server successfully started on port " + port);
        } catch (IOException e) {
            System.out.println("Failed to start MCP Server: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public void stopServer() {
        running = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        
        if (threadPool != null) {
            threadPool.shutdown();
        }
        
        System.out.println("MCP Server stopped");
    }
    
    public void setPort(int port) {
        this.port = port;
    }
    
    public int getPort() {
        return port;
    }
    
    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        contextProvider.setCurrentProgram(program);
    }
    
    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        contextProvider.setCurrentProgram(null);
    }
    
    @Override
    public void dispose() {
        stopServer();
        super.dispose();
    }
}