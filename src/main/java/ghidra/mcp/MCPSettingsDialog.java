package ghidra.mcp;

import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.security.SecureRandom;
import java.util.Properties;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.SpinnerNumberModel;
import javax.swing.JSeparator;

import docking.DialogComponentProvider;
import ghidra.util.Msg;

/**
 * Settings dialog for the GhidraMCP plugin.
 *
 * Accessible from Ghidra's menu: MCP > Settings.
 * Allows the user to configure all server properties, generate API keys,
 * and write/copy the MCP client configuration.
 */
public class MCPSettingsDialog extends DialogComponentProvider {

    private final MCPServerPlugin plugin;

    // Form fields
    private JSpinner portSpinner;
    private JCheckBox localhostOnlyCheckbox;
    private JPasswordField apiKeyField;
    private JCheckBox autoStartCheckbox;
    private JCheckBox bridgeEnabledCheckbox;

    public MCPSettingsDialog(MCPServerPlugin plugin) {
        super("GhidraMCP Settings", true, true, true, false);
        this.plugin = plugin;

        addWorkPanel(buildMainPanel());
        addOKButton();
        addCancelButton();

        // Populate fields from current configuration
        populateFromConfig();

        setOkEnabled(true);
    }

    private void populateFromConfig() {
        Properties config = plugin.getConfig();
        portSpinner.setValue(Integer.parseInt(config.getProperty("port", "8765")));
        localhostOnlyCheckbox.setSelected(
                Boolean.parseBoolean(config.getProperty("localhost_only", "true")));
        apiKeyField.setText(config.getProperty("api_key", ""));
        autoStartCheckbox.setSelected(
                Boolean.parseBoolean(config.getProperty("auto_start", "true")));
        bridgeEnabledCheckbox.setSelected(
                Boolean.parseBoolean(config.getProperty("bridge_enabled", "true")));
    }

    private JPanel buildMainPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        int row = 0;

        // ---- Config file path ----
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        String configPath = plugin.getConfigFilePath();
        JLabel configPathLabel = new JLabel("Config file: " + configPath);
        configPathLabel.setFont(configPathLabel.getFont().deriveFont(Font.ITALIC, 11f));
        panel.add(configPathLabel, gbc);
        gbc.gridwidth = 1;
        row++;

        // ---- Port ----
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        SpinnerNumberModel portModel = new SpinnerNumberModel(8765, 1, 65535, 1);
        portSpinner = new JSpinner(portModel);
        portSpinner.setEditor(new JSpinner.NumberEditor(portSpinner, "#"));
        panel.add(portSpinner, gbc);
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        row++;

        // ---- Localhost Only ----
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(new JLabel("Localhost Only:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        localhostOnlyCheckbox = new JCheckBox("Only accept local connections");
        panel.add(localhostOnlyCheckbox, gbc);
        gbc.gridwidth = 1;
        row++;

        // ---- API Key ----
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        apiKeyField = new JPasswordField(30);
        apiKeyField.setEchoChar('\u2022'); // bullet character
        panel.add(apiKeyField, gbc);
        gbc.gridx = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JPanel apiKeyBtnPanel = new JPanel();
        apiKeyBtnPanel.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 2, 0));
        JButton generateBtn = new JButton("Generate");
        generateBtn.addActionListener(e -> apiKeyField.setText(generateApiKey()));
        apiKeyBtnPanel.add(generateBtn);
        JToggleButton showBtn = new JToggleButton("Show");
        showBtn.addActionListener(e -> {
            if (showBtn.isSelected()) {
                apiKeyField.setEchoChar((char) 0); // show plaintext
                showBtn.setText("Hide");
            } else {
                apiKeyField.setEchoChar('\u2022');
                showBtn.setText("Show");
            }
        });
        apiKeyBtnPanel.add(showBtn);
        panel.add(apiKeyBtnPanel, gbc);
        row++;

        // ---- Auto Start ----
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(new JLabel("Auto Start:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        autoStartCheckbox = new JCheckBox("Start server when plugin loads");
        panel.add(autoStartCheckbox, gbc);
        gbc.gridwidth = 1;
        row++;

        // ---- Bridge Enabled ----
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(new JLabel("Bridge Enabled:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        bridgeEnabledCheckbox = new JCheckBox("Auto-launch the Go bridge");
        panel.add(bridgeEnabledCheckbox, gbc);
        gbc.gridwidth = 1;
        row++;

        // ---- Separator ----
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 5, 5, 5);
        panel.add(new JSeparator(), gbc);
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(5, 5, 5, 5);
        row++;

        // ---- MCP Client Config buttons ----
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        panel.add(new JLabel("MCP Client Config:"), gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        JPanel buttonPanel = new JPanel();
        JButton writeConfigBtn = new JButton("Write to Claude Config");
        writeConfigBtn.addActionListener(e -> writeToClaudeConfig());
        buttonPanel.add(writeConfigBtn);

        JButton copyConfigBtn = new JButton("Copy to Clipboard");
        copyConfigBtn.addActionListener(e -> copyConfigToClipboard());
        buttonPanel.add(copyConfigBtn);
        panel.add(buttonPanel, gbc);
        row++;

        // ---- Restart warning ----
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        gbc.insets = new Insets(10, 5, 5, 5);
        JLabel warningLabel = new JLabel(
                "<html><i>\u26A0 Changes require a server restart to take effect. "
                        + "Use MCP \u2192 Toggle Server to restart.</i></html>");
        warningLabel.setForeground(new Color(180, 120, 0));
        panel.add(warningLabel, gbc);

        return panel;
    }

    /**
     * Generate a cryptographically random 32-character hex API key.
     * Package-private and static so it can be unit-tested without Swing.
     */
    static String generateApiKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(32);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void writeToClaudeConfig() {
        String bridgePath = plugin.getBridgePath();
        if (bridgePath == null) {
            setStatusText("Bridge binary not found \u2014 cannot generate config");
            return;
        }
        int port = (Integer) portSpinner.getValue();
        String apiKey = new String(apiKeyField.getPassword()).trim();
        try {
            MCPConfigHelper.mergeIntoClaudeConfig(bridgePath, port, apiKey);
            setStatusText("Written to Claude Desktop config successfully");
        } catch (Exception e) {
            setStatusText("Error writing config: " + e.getMessage());
        }
    }

    private void copyConfigToClipboard() {
        String bridgePath = plugin.getBridgePath();
        if (bridgePath == null) {
            setStatusText("Bridge binary not found \u2014 cannot generate config");
            return;
        }
        int port = (Integer) portSpinner.getValue();
        String apiKey = new String(apiKeyField.getPassword()).trim();
        String snippet = MCPConfigHelper.getConfigSnippet(bridgePath, port, apiKey);
        try {
            StringSelection selection = new StringSelection(snippet);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            setStatusText("MCP config copied to clipboard");
        } catch (Exception e) {
            setStatusText("Failed to copy: " + e.getMessage());
        }
    }

    @Override
    protected void okCallback() {
        // Validate port
        int port = (Integer) portSpinner.getValue();
        if (port < 1 || port > 65535) {
            setStatusText("Port must be between 1 and 65535");
            return;
        }

        boolean localhostOnly = localhostOnlyCheckbox.isSelected();
        String apiKey = new String(apiKeyField.getPassword()).trim();

        // Security warning: remote access without API key
        if (!localhostOnly && apiKey.isEmpty()) {
            int result = JOptionPane.showConfirmDialog(getComponent(),
                    "You are allowing remote connections without an API key.\n"
                            + "This is a security risk. Are you sure?",
                    "Security Warning",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (result != JOptionPane.YES_OPTION) {
                return;
            }
        }

        // Save configuration
        plugin.updateConfiguration(
                port,
                localhostOnly,
                apiKey,
                autoStartCheckbox.isSelected(),
                bridgeEnabledCheckbox.isSelected());

        // Offer restart if server is running
        if (plugin.isServerRunning()) {
            int result = JOptionPane.showConfirmDialog(getComponent(),
                    "The server is currently running. Restart now to apply changes?",
                    "Restart Server",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (result == JOptionPane.YES_OPTION) {
                plugin.restartServer();
            }
        }

        close();
    }

    @Override
    protected void cancelCallback() {
        close();
    }
}
