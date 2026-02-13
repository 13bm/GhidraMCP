package ghidra.mcp;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.util.Msg;

/**
 * Manages the Claude Desktop MCP configuration.
 *
 * Safely merges the GhidraMCP server entry into the existing
 * claude_desktop_config.json without touching any other MCP servers
 * the user may have configured.
 */
public class MCPConfigHelper {

    /**
     * Merge the GhidraMCP entry into Claude Desktop's config file.
     * Only touches the "mcpServers.ghidra" key — all other keys are preserved.
     *
     * @param bridgePath Absolute path to the Go bridge binary
     * @param port       The port the Java server is listening on
     * @param apiKey     The API key (empty string if none)
     */
    public static void mergeIntoClaudeConfig(String bridgePath, int port, String apiKey) {
        File configFile = getClaudeConfigFile();
        if (configFile == null) {
            Msg.warn(MCPConfigHelper.class, "Could not determine Claude Desktop config path");
            return;
        }

        try {
            JsonObject root;

            // Load existing config or create new
            if (configFile.exists()) {
                try (FileReader reader = new FileReader(configFile)) {
                    root = JsonParser.parseReader(reader).getAsJsonObject();
                }
                Msg.info(MCPConfigHelper.class, "Loaded existing Claude config: " + configFile.getAbsolutePath());
            } else {
                root = new JsonObject();
                // Ensure parent directory exists
                configFile.getParentFile().mkdirs();
                Msg.info(MCPConfigHelper.class, "Creating new Claude config: " + configFile.getAbsolutePath());
            }

            // Get or create mcpServers object
            JsonObject mcpServers;
            if (root.has("mcpServers") && root.get("mcpServers").isJsonObject()) {
                mcpServers = root.getAsJsonObject("mcpServers");
            } else {
                mcpServers = new JsonObject();
                root.add("mcpServers", mcpServers);
            }

            // Build the ghidra server entry — use GHIDRA_API_KEY env var
            // instead of --api-key CLI flag to keep the key out of the process table.
            JsonObject ghidraEntry = new JsonObject();
            ghidraEntry.addProperty("command", bridgePath);

            JsonArray args = new JsonArray();
            args.add("--host");
            args.add("localhost");
            args.add("--port");
            args.add(String.valueOf(port));
            ghidraEntry.add("args", args);

            if (apiKey != null && !apiKey.isEmpty()) {
                JsonObject env = new JsonObject();
                env.addProperty("GHIDRA_API_KEY", apiKey);
                ghidraEntry.add("env", env);
            }

            // Set ONLY the ghidra key — preserve everything else
            mcpServers.add("ghidra", ghidraEntry);

            // Write back with pretty printing
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            try (FileWriter writer = new FileWriter(configFile)) {
                writer.write(gson.toJson(root));
            }

            Msg.info(MCPConfigHelper.class,
                "Updated Claude Desktop config with GhidraMCP entry: " + configFile.getAbsolutePath());

        } catch (IOException e) {
            Msg.error(MCPConfigHelper.class,
                "Error updating Claude Desktop config: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(MCPConfigHelper.class,
                "Error parsing Claude Desktop config (may be malformed): " + e.getMessage());
        }
    }

    /**
     * Print the MCP config snippet to the Ghidra console for manual setup.
     *
     * @param bridgePath Absolute path to the Go bridge binary
     * @param port       The port the Java server is listening on
     * @param apiKey     The API key (empty string if none)
     */
    public static void printConfigToConsole(String bridgePath, int port, String apiKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n");
        sb.append("=== GhidraMCP Configuration ===\n");
        sb.append("\n");
        sb.append("Add the following to your Claude Desktop config\n");

        File configFile = getClaudeConfigFile();
        if (configFile != null) {
            sb.append("(").append(configFile.getAbsolutePath()).append("):\n");
        } else {
            sb.append("(claude_desktop_config.json):\n");
        }

        sb.append("\n");
        sb.append("{\n");
        sb.append("  \"mcpServers\": {\n");
        sb.append("    \"ghidra\": {\n");
        sb.append("      \"command\": \"").append(escapeJson(bridgePath)).append("\",\n");
        sb.append("      \"args\": [\"--host\", \"localhost\", \"--port\", \"").append(port).append("\"]");

        if (apiKey != null && !apiKey.isEmpty()) {
            sb.append(",\n");
            sb.append("      \"env\": {\n");
            sb.append("        \"GHIDRA_API_KEY\": \"").append(maskApiKey(apiKey)).append("\"\n");
            sb.append("      }");
        }

        sb.append("\n");
        sb.append("    }\n");
        sb.append("  }\n");
        sb.append("}\n");
        sb.append("\n");
        sb.append("================================\n");

        Msg.info(MCPConfigHelper.class, sb.toString());
    }

    /**
     * Get the JSON snippet for copying to clipboard.
     */
    public static String getConfigSnippet(String bridgePath, int port, String apiKey) {
        JsonObject ghidraEntry = new JsonObject();
        ghidraEntry.addProperty("command", bridgePath);

        JsonArray args = new JsonArray();
        args.add("--host");
        args.add("localhost");
        args.add("--port");
        args.add(String.valueOf(port));
        ghidraEntry.add("args", args);

        // Use GHIDRA_API_KEY env var instead of --api-key CLI flag.
        if (apiKey != null && !apiKey.isEmpty()) {
            JsonObject env = new JsonObject();
            env.addProperty("GHIDRA_API_KEY", apiKey);
            ghidraEntry.add("env", env);
        }

        JsonObject mcpServers = new JsonObject();
        mcpServers.add("ghidra", ghidraEntry);

        JsonObject root = new JsonObject();
        root.add("mcpServers", mcpServers);

        return new GsonBuilder().setPrettyPrinting().create().toJson(root);
    }

    /**
     * Determine the Claude Desktop config file path based on the current OS.
     */
    private static File getClaudeConfigFile() {
        String os = System.getProperty("os.name", "").toLowerCase();

        if (os.contains("win")) {
            // Windows: %APPDATA%/Claude/claude_desktop_config.json
            String appData = System.getenv("APPDATA");
            if (appData != null) {
                return new File(appData, "Claude/claude_desktop_config.json");
            }
        } else if (os.contains("mac") || os.contains("darwin")) {
            // macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
            String home = System.getProperty("user.home");
            if (home != null) {
                return new File(home, "Library/Application Support/Claude/claude_desktop_config.json");
            }
        } else {
            // Linux: ~/.config/Claude/claude_desktop_config.json
            String home = System.getProperty("user.home");
            if (home != null) {
                return new File(home, ".config/Claude/claude_desktop_config.json");
            }
        }

        return null;
    }

    /**
     * JSON string escaping for backslashes, quotes, and control characters.
     */
    private static String escapeJson(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * Mask an API key for safe display in console output.
     * Shows the first 4 characters followed by asterisks.
     */
    private static String maskApiKey(String key) {
        if (key == null || key.length() <= 4) return "****";
        return key.substring(0, 4) + "****" + "****" + "****";
    }
}
