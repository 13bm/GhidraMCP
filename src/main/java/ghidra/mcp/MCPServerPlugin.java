package ghidra.mcp;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidraMCP",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Model Context Protocol Server for Ghidra",
    description = "Provides an MCP server for AI model integration with Ghidra"
)
public class MCPServerPlugin extends ProgramPlugin {
    private MCPServer server;
    private MCPBridgeLauncher bridgeLauncher;
    private Properties config;
    private File configFile;
    private ToggleDockingAction toggleServerAction;
    private static final String CONFIG_FILENAME = "GhidraMCP.properties";

    // Configuration property keys
    private static final String PROP_PORT = "port";
    private static final String PROP_LOCALHOST_ONLY = "localhost_only";
    private static final String PROP_API_KEY = "api_key";
    private static final String PROP_AUTO_START = "auto_start";
    private static final String PROP_BRIDGE_ENABLED = "bridge_enabled";

    // Default configuration values
    private static final int DEFAULT_PORT = 8765;
    private static final boolean DEFAULT_LOCALHOST_ONLY = true;
    private static final boolean DEFAULT_AUTO_START = true;
    private static final boolean DEFAULT_BRIDGE_ENABLED = true;

    public MCPServerPlugin(PluginTool tool) {
        super(tool);

        // Initialize the configuration
        config = new Properties();
        loadConfiguration();

        // Create the server and bridge launcher
        server = new MCPServer(tool);
        bridgeLauncher = new MCPBridgeLauncher();
    }

    private void loadConfiguration() {
        try {
            // Get the user configuration directory
            File userConfigDir = Application.getUserSettingsDirectory();
            configFile = new File(userConfigDir, CONFIG_FILENAME);

            // Load existing configuration if available
            if (configFile.exists()) {
                try (FileInputStream in = new FileInputStream(configFile)) {
                    config.load(in);
                    Msg.info(this, "Loaded MCP Server configuration from " + configFile.getAbsolutePath());
                }
            } else {
                // Set default configuration
                config.setProperty(PROP_PORT, String.valueOf(DEFAULT_PORT));
                config.setProperty(PROP_LOCALHOST_ONLY, String.valueOf(DEFAULT_LOCALHOST_ONLY));
                config.setProperty(PROP_API_KEY, "");
                config.setProperty(PROP_AUTO_START, String.valueOf(DEFAULT_AUTO_START));
                config.setProperty(PROP_BRIDGE_ENABLED, String.valueOf(DEFAULT_BRIDGE_ENABLED));

                // Save the default configuration
                saveConfiguration();
                Msg.info(this, "Created default MCP Server configuration");
            }
        } catch (IOException e) {
            Msg.error(this, "Error loading MCP Server configuration: " + e.getMessage());

            // Set fallback defaults in memory
            config.setProperty(PROP_PORT, String.valueOf(DEFAULT_PORT));
            config.setProperty(PROP_LOCALHOST_ONLY, String.valueOf(DEFAULT_LOCALHOST_ONLY));
            config.setProperty(PROP_API_KEY, "");
            config.setProperty(PROP_AUTO_START, String.valueOf(DEFAULT_AUTO_START));
            config.setProperty(PROP_BRIDGE_ENABLED, String.valueOf(DEFAULT_BRIDGE_ENABLED));
        }
    }

    private void saveConfiguration() {
        try {
            if (configFile != null) {
                try (FileOutputStream out = new FileOutputStream(configFile)) {
                    config.store(out, "GhidraMCP Configuration");
                    Msg.info(this, "Saved MCP Server configuration");
                }
            }
        } catch (IOException e) {
            Msg.error(this, "Error saving MCP Server configuration: " + e.getMessage());
        }
    }

    private void setupActions() {
        // Toggle action to start/stop the server
        toggleServerAction = new ToggleDockingAction("Toggle MCP Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                boolean isSelected = isSelected();
                if (isSelected) {
                    startServer();
                } else {
                    stopServer();
                }
            }
        };
        toggleServerAction.setMenuBarData(new MenuData(new String[] { "MCP", "Toggle Server" }));
        toggleServerAction.setDescription("Start/Stop the MCP Server");
        toggleServerAction.setSelected(Boolean.parseBoolean(config.getProperty(PROP_AUTO_START)));
        tool.addAction(toggleServerAction);

        // Action to copy MCP config snippet to clipboard
        DockingAction copyConfigAction = new DockingAction("Copy MCP Config", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                copyMcpConfigToClipboard();
            }
        };
        copyConfigAction.setMenuBarData(new MenuData(new String[] { "MCP", "Copy MCP Config" }));
        copyConfigAction.setDescription("Copy the Claude Desktop MCP configuration to clipboard");
        tool.addAction(copyConfigAction);

        // Action to open settings dialog
        DockingAction settingsAction = new DockingAction("MCP Settings", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                MCPSettingsDialog dialog = new MCPSettingsDialog(MCPServerPlugin.this);
                tool.showDialog(dialog);
            }
        };
        settingsAction.setMenuBarData(new MenuData(new String[] { "MCP", "Settings" }));
        settingsAction.setDescription("Open MCP Server settings");
        tool.addAction(settingsAction);
    }

    private void copyMcpConfigToClipboard() {
        int port = Integer.parseInt(config.getProperty(PROP_PORT, String.valueOf(DEFAULT_PORT)));
        String apiKey = config.getProperty(PROP_API_KEY, "");
        String bridgePath = bridgeLauncher.getBridgePath();

        if (bridgePath == null) {
            Msg.error(this, "Could not find bridge binary path — cannot generate config");
            return;
        }

        String snippet = MCPConfigHelper.getConfigSnippet(bridgePath, port, apiKey);

        try {
            StringSelection selection = new StringSelection(snippet);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            Msg.info(this, "MCP config copied to clipboard!");
        } catch (Exception e) {
            Msg.error(this, "Failed to copy to clipboard: " + e.getMessage());
            // Print it to console as fallback
            MCPConfigHelper.printConfigToConsole(bridgePath, port, apiKey);
        }
    }

    private void startServer() {
        // Configure the server
        int port = Integer.parseInt(config.getProperty(PROP_PORT, String.valueOf(DEFAULT_PORT)));
        boolean localhostOnly = Boolean.parseBoolean(config.getProperty(PROP_LOCALHOST_ONLY, String.valueOf(DEFAULT_LOCALHOST_ONLY)));
        String apiKey = config.getProperty(PROP_API_KEY, "");
        boolean bridgeEnabled = Boolean.parseBoolean(config.getProperty(PROP_BRIDGE_ENABLED, String.valueOf(DEFAULT_BRIDGE_ENABLED)));

        server.setPort(port);
        server.setRestrictToLocalhost(localhostOnly);
        if (!apiKey.isEmpty()) {
            server.setApiKey(apiKey);
        }

        // Start the Java TCP server
        server.startServer();

        // Log security settings
        if (localhostOnly) {
            Msg.info(this, "MCP Server accepting localhost connections only");
        } else {
            Msg.warn(this, "MCP Server accepting connections from any host");
        }

        if (!apiKey.isEmpty()) {
            Msg.info(this, "MCP Server authentication enabled");
        } else {
            Msg.warn(this, "MCP Server authentication disabled");
        }

        // Start the Go bridge if enabled
        if (bridgeEnabled) {
            bridgeLauncher.start(port, apiKey);

            // Print config to console for reference (use MCP > Settings to write to Claude config)
            String bridgePath = bridgeLauncher.getBridgePath();
            if (bridgePath != null) {
                MCPConfigHelper.printConfigToConsole(bridgePath, port, apiKey);
            }
        } else {
            Msg.info(this, "MCP bridge auto-launch disabled in configuration");
        }
    }

    private void stopServer() {
        bridgeLauncher.stop();
        server.stopServer();
    }

    @Override
    public void init() {
        super.init();

        Msg.info(this, "Initializing GhidraMCP Plugin v" + getPluginVersionString());

        // Setup UI actions in the Swing thread
        SwingUtilities.invokeLater(() -> {
            setupActions();

            // Auto-start the server if configured
            if (Boolean.parseBoolean(config.getProperty(PROP_AUTO_START, String.valueOf(DEFAULT_AUTO_START)))) {
                startServer();
            }
        });
    }

    private String getPluginVersionString() {
        // Read version from the running Ghidra instance — matches extension.properties
        // automatically since the extension version must equal the Ghidra version.
        return Application.getApplicationVersion();
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        server.setCurrentProgram(program);
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        server.setCurrentProgram(null);
    }

    // ---- Package-private accessors for MCPSettingsDialog ----

    Properties getConfig() {
        // Return a defensive copy to prevent race conditions between the
        // Settings dialog (Swing EDT) and the server thread.
        Properties copy = new Properties();
        copy.putAll(config);
        return copy;
    }

    String getConfigFilePath() {
        return configFile != null ? configFile.getAbsolutePath() : "(unknown)";
    }

    boolean isServerRunning() {
        return server.isRunning();
    }

    String getBridgePath() {
        return bridgeLauncher.getBridgePath();
    }

    void updateConfiguration(int port, boolean localhostOnly, String apiKey,
                              boolean autoStart, boolean bridgeEnabled) {
        config.setProperty(PROP_PORT, String.valueOf(port));
        config.setProperty(PROP_LOCALHOST_ONLY, String.valueOf(localhostOnly));
        config.setProperty(PROP_API_KEY, apiKey);
        config.setProperty(PROP_AUTO_START, String.valueOf(autoStart));
        config.setProperty(PROP_BRIDGE_ENABLED, String.valueOf(bridgeEnabled));
        saveConfiguration();
    }

    void restartServer() {
        stopServer();
        startServer();
        if (toggleServerAction != null) {
            toggleServerAction.setSelected(server.isRunning());
        }
    }

    @Override
    public void dispose() {
        stopServer();
        super.dispose();
    }
}
