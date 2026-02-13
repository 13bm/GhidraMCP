package ghidra.mcp;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.util.Msg;

/**
 * Manages the lifecycle of the MCP Go bridge process.
 *
 * The bridge binary is embedded in the extension's data/os/ directory
 * with platform-specific subdirectories (linux_x86_64, win_x86_64,
 * mac_x86_64, mac_aarch64). This launcher finds the correct binary
 * for the current platform and manages its lifecycle.
 */
public class MCPBridgeLauncher {
    private Process bridgeProcess;
    private Thread stderrLogThread;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private static final String BRIDGE_BINARY_NAME = "mcp_bridge";

    /**
     * Start the Go bridge process.
     *
     * @param port    The port the Java server is listening on
     * @param apiKey  The API key for authentication (empty string if none)
     */
    public void start(int port, String apiKey) {
        if (running.get() && bridgeProcess != null && bridgeProcess.isAlive()) {
            Msg.info(this, "MCP bridge already running");
            return;
        }

        try {
            String platDir = Platform.CURRENT_PLATFORM.getDirectoryName();
            String ext = Platform.CURRENT_PLATFORM.getExecutableExtension();
            if (ext == null) {
                ext = "";
            }

            ResourceFile binDir = Application.getModuleDataSubDirectory("os/" + platDir);
            File bridge = new File(binDir.getFile(false), BRIDGE_BINARY_NAME + ext);

            if (!bridge.exists()) {
                Msg.error(this, "MCP bridge binary not found: " + bridge.getAbsolutePath());
                Msg.error(this, "Platform: " + platDir + ", expected binary: " + BRIDGE_BINARY_NAME + ext);
                return;
            }

            // Ensure executable permission on Unix-like systems (no-op on Windows)
            bridge.setExecutable(true);

            // SEC: Pass the API key via GHIDRA_API_KEY environment variable
            // instead of --api-key CLI flag to prevent leaking the secret in the
            // process argument list (visible via ps / Task Manager).  The Go bridge
            // prefers GHIDRA_API_KEY over --api-key when both are present.
            List<String> command = new ArrayList<>();
            command.add(bridge.getAbsolutePath());
            command.add("--host");
            command.add("localhost");
            command.add("--port");
            command.add(String.valueOf(port));

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(false);

            // Inject the API key into the child process's environment only.
            if (apiKey != null && !apiKey.isEmpty()) {
                pb.environment().put("GHIDRA_API_KEY", apiKey);
            }

            Msg.info(this, "Starting MCP bridge: " + bridge.getAbsolutePath());
            bridgeProcess = pb.start();
            running.set(true);

            // Log stderr from the bridge process in a background thread
            stderrLogThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(bridgeProcess.getErrorStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        Msg.info(this, "[mcp-bridge] " + line);
                    }
                } catch (IOException e) {
                    // Process ended or stream closed — expected during shutdown
                }
            }, "mcp-bridge-stderr");
            stderrLogThread.setDaemon(true);
            stderrLogThread.start();

            // Monitor for unexpected exits
            bridgeProcess.onExit().thenAccept(p -> {
                running.set(false);
                int exitCode = p.exitValue();
                if (exitCode != 0) {
                    Msg.warn(this, "MCP bridge exited unexpectedly with code " + exitCode);
                } else {
                    Msg.info(this, "MCP bridge exited normally");
                }
            });

            Msg.info(this, "MCP bridge started successfully (PID: " + bridgeProcess.pid() + ")");

        } catch (IOException e) {
            Msg.error(this, "Failed to start MCP bridge: " + e.getMessage());
            running.set(false);
        }
    }

    /**
     * Stop the Go bridge process gracefully, with a forced kill fallback.
     */
    public void stop() {
        if (bridgeProcess == null || !bridgeProcess.isAlive()) {
            running.set(false);
            return;
        }

        Msg.info(this, "Stopping MCP bridge...");

        // Try graceful shutdown first
        bridgeProcess.destroy();

        try {
            // Wait up to 5 seconds for graceful exit
            boolean exited = bridgeProcess.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!exited) {
                Msg.warn(this, "MCP bridge did not exit gracefully, forcing...");
                bridgeProcess.destroyForcibly();
                bridgeProcess.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            bridgeProcess.destroyForcibly();
            Thread.currentThread().interrupt();
        }

        running.set(false);
        Msg.info(this, "MCP bridge stopped");
    }

    /**
     * Check if the bridge process is currently running.
     */
    public boolean isRunning() {
        return running.get() && bridgeProcess != null && bridgeProcess.isAlive();
    }

    /**
     * Get the path to the bridge binary for the current platform.
     * Returns null if the binary is not found.
     */
    public String getBridgePath() {
        try {
            String platDir = Platform.CURRENT_PLATFORM.getDirectoryName();
            String ext = Platform.CURRENT_PLATFORM.getExecutableExtension();
            if (ext == null) ext = "";

            ResourceFile binDir = Application.getModuleDataSubDirectory("os/" + platDir);
            File bridge = new File(binDir.getFile(false), BRIDGE_BINARY_NAME + ext);

            if (bridge.exists()) {
                return bridge.getAbsolutePath();
            }
        } catch (Exception e) {
            Msg.error(this, "Error locating bridge binary: " + e.getMessage());
        }
        return null;
    }
}
