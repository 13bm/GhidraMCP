package ghidra.mcp;

import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * TCP server that accepts MCP client connections and dispatches requests
 * to the Ghidra context provider.
 *
 * This is NOT a Ghidra plugin — it is a plain server object owned by
 * {@link MCPServerPlugin}, which is the actual plugin entry point.
 */
public class MCPServer {
    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private volatile boolean running = false;
    private int port = 8765;
    private boolean restrictToLocalhost = true;
    private String apiKey = "";
    private MCPContextProvider contextProvider;
    private Thread listenerThread;

    /** Socket read timeout for client connections (30 seconds). */
    private static final int CLIENT_SOCKET_TIMEOUT_MS = 30_000;

    public MCPServer(PluginTool tool) {
        contextProvider = new MCPContextProvider(tool);
    }

    public void startServer() {
        if (running) {
            Msg.info(this, "MCP Server already running");
            return;
        }

        try {
            if (restrictToLocalhost) {
                Msg.info(this, "MCP Server binding to localhost:" + port);
                serverSocket = new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
            } else {
                Msg.info(this, "MCP Server binding to all interfaces on port " + port);
                serverSocket = new ServerSocket(port);
            }

            threadPool = new ThreadPoolExecutor(2, 8, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(16));
            running = true;

            if (apiKey == null || apiKey.isEmpty()) {
                Msg.warn(this, "GhidraMCP: Authentication is DISABLED. Set an API key for production use.");
                if (!restrictToLocalhost) {
                    Msg.error(this, "GhidraMCP: Server is listening on all interfaces WITHOUT authentication!");
                }
            }

            Msg.info(this, "MCP Server socket created successfully");

            listenerThread = new Thread(() -> {
                Msg.info(this, "MCP Server listener thread started");
                while (running) {
                    try {
                        Msg.info(this, "MCP Server waiting for connections on port " + port);
                        Socket clientSocket = serverSocket.accept();
                        Msg.info(this, "MCP Server: Client connected from " + clientSocket.getInetAddress());

                        // Set socket timeout to prevent slow/stalled clients from
                        // holding a thread indefinitely (DoS mitigation).
                        try {
                            clientSocket.setSoTimeout(CLIENT_SOCKET_TIMEOUT_MS);
                        } catch (SocketException se) {
                            Msg.warn(this, "Could not set socket timeout: " + se.getMessage());
                        }

                        MCPClientHandler handler = new MCPClientHandler(clientSocket, contextProvider);
                        if (!apiKey.isEmpty()) {
                            handler.setRequireAuthentication(true);
                            handler.setApiKey(apiKey);
                        }

                        try {
                            threadPool.submit(handler);
                        } catch (java.util.concurrent.RejectedExecutionException e) {
                            Msg.warn(this, "Server busy, rejecting connection from " + clientSocket.getInetAddress());
                            try { clientSocket.close(); } catch (IOException ignored) {}
                        }
                    } catch (IOException e) {
                        if (running) {
                            Msg.error(this, "MCP Server socket error: " + e.getMessage());
                        }
                    }
                }
            });
            listenerThread.setDaemon(true);
            listenerThread.start();

            Msg.info(this, "MCP Server successfully started on port " + port);
        } catch (BindException e) {
            Msg.error(this, "Port " + port + " is already in use. Close the conflicting "
                    + "application or choose a different port in MCP > Settings. "
                    + "Details: " + e.getMessage());
        } catch (IOException e) {
            Msg.error(this, "Failed to start MCP Server: " + e.getMessage());
        }
    }

    public void stopServer() {
        running = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                Msg.error(this, "Error closing server socket: " + e.getMessage());
            }
        }

        if (threadPool != null) {
            try {
                threadPool.shutdown();
                if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                    threadPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                threadPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        // Shut down the async decompiler pool and clear pending tasks.
        if (contextProvider != null) {
            contextProvider.shutdown();
        }

        Msg.info(this, "MCP Server stopped");
    }

    // ----- Program lifecycle (called by MCPServerPlugin) -----

    public void setCurrentProgram(Program program) {
        contextProvider.setCurrentProgram(program);
    }

    // ----- Configuration accessors -----

    public void setPort(int port) {
        this.port = port;
    }

    public int getPort() {
        return port;
    }

    public void setRestrictToLocalhost(boolean restrictToLocalhost) {
        this.restrictToLocalhost = restrictToLocalhost;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public boolean isRunning() {
        return running;
    }
}
