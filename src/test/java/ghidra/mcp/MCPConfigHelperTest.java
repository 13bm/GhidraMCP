package ghidra.mcp;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.Test;

/**
 * Tests for MCPConfigHelper — config snippet generation and JSON escaping.
 * Pure logic, no Ghidra runtime needed.
 */
public class MCPConfigHelperTest {

    @Test
    public void testGetConfigSnippetBasic() {
        String snippet = MCPConfigHelper.getConfigSnippet("/usr/bin/mcp_bridge", 8765, "");
        JsonObject root = JsonParser.parseString(snippet).getAsJsonObject();

        assertTrue("Should have mcpServers", root.has("mcpServers"));
        JsonObject servers = root.getAsJsonObject("mcpServers");
        assertTrue("Should have ghidra entry", servers.has("ghidra"));

        JsonObject ghidra = servers.getAsJsonObject("ghidra");
        assertEquals("/usr/bin/mcp_bridge", ghidra.get("command").getAsString());

        // Args should be: --host localhost --port 8765
        assertEquals(4, ghidra.getAsJsonArray("args").size());
        assertEquals("--host", ghidra.getAsJsonArray("args").get(0).getAsString());
        assertEquals("localhost", ghidra.getAsJsonArray("args").get(1).getAsString());
        assertEquals("--port", ghidra.getAsJsonArray("args").get(2).getAsString());
        assertEquals("8765", ghidra.getAsJsonArray("args").get(3).getAsString());
    }

    @Test
    public void testGetConfigSnippetWithApiKey() {
        String snippet = MCPConfigHelper.getConfigSnippet("/path/bridge", 9999, "mykey");
        JsonObject root = JsonParser.parseString(snippet).getAsJsonObject();
        JsonObject ghidra = root.getAsJsonObject("mcpServers").getAsJsonObject("ghidra");

        // Args should NOT include --api-key; key goes in env block instead
        assertEquals(4, ghidra.getAsJsonArray("args").size());
        assertTrue("Should have env block", ghidra.has("env"));
        JsonObject env = ghidra.getAsJsonObject("env");
        assertEquals("mykey", env.get("GHIDRA_API_KEY").getAsString());
    }

    @Test
    public void testGetConfigSnippetNullApiKey() {
        // null apiKey should not add env block
        String snippet = MCPConfigHelper.getConfigSnippet("/path/bridge", 8765, null);
        JsonObject root = JsonParser.parseString(snippet).getAsJsonObject();
        JsonObject ghidra = root.getAsJsonObject("mcpServers").getAsJsonObject("ghidra");
        assertEquals(4, ghidra.getAsJsonArray("args").size());
        assertFalse("Should not have env block", ghidra.has("env"));
    }

    @Test
    public void testGetConfigSnippetWindowsPath() {
        // Backslashes in Windows paths should be properly handled in JSON
        String snippet = MCPConfigHelper.getConfigSnippet("C:\\Users\\test\\mcp_bridge.exe", 8765, "");
        JsonObject root = JsonParser.parseString(snippet).getAsJsonObject();
        JsonObject ghidra = root.getAsJsonObject("mcpServers").getAsJsonObject("ghidra");
        assertEquals("C:\\Users\\test\\mcp_bridge.exe", ghidra.get("command").getAsString());
    }

    @Test
    public void testGetConfigSnippetIsValidJson() {
        String snippet = MCPConfigHelper.getConfigSnippet("/path/bridge", 8765, "key\"with\"quotes");
        // Should not throw — must be valid JSON even with quotes in the api key
        JsonObject root = JsonParser.parseString(snippet).getAsJsonObject();
        assertNotNull(root);
    }

    @Test
    public void testGetConfigSnippetCustomPort() {
        String snippet = MCPConfigHelper.getConfigSnippet("/bridge", 12345, "");
        JsonObject root = JsonParser.parseString(snippet).getAsJsonObject();
        JsonObject ghidra = root.getAsJsonObject("mcpServers").getAsJsonObject("ghidra");
        assertEquals("12345", ghidra.getAsJsonArray("args").get(3).getAsString());
    }

    @Test
    public void testGetConfigSnippetCustomPortAndKey() {
        // Verify non-default port + key are correctly reflected in the snippet
        String snippet = MCPConfigHelper.getConfigSnippet("/opt/ghidra/mcp_bridge", 9090, "a1b2c3d4");
        JsonObject root = JsonParser.parseString(snippet).getAsJsonObject();
        JsonObject ghidra = root.getAsJsonObject("mcpServers").getAsJsonObject("ghidra");

        assertEquals("/opt/ghidra/mcp_bridge", ghidra.get("command").getAsString());
        assertEquals("9090", ghidra.getAsJsonArray("args").get(3).getAsString());
        // API key should be in env block, not args
        assertEquals(4, ghidra.getAsJsonArray("args").size());
        assertTrue("Should have env block", ghidra.has("env"));
        assertEquals("a1b2c3d4", ghidra.getAsJsonObject("env").get("GHIDRA_API_KEY").getAsString());
    }
}
