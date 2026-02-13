package ghidra.mcp;

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

/**
 * Tests for MCPSettingsDialog — API key generation logic.
 * Pure logic, no Ghidra runtime or Swing needed.
 */
public class MCPSettingsDialogTest {

    @Test
    public void testGenerateApiKeyLength() {
        String key = MCPSettingsDialog.generateApiKey();
        assertEquals("API key should be 32 characters", 32, key.length());
    }

    @Test
    public void testGenerateApiKeyIsHex() {
        String key = MCPSettingsDialog.generateApiKey();
        assertTrue("API key should only contain hex characters [0-9a-f]",
                key.matches("[0-9a-f]+"));
    }

    @Test
    public void testGenerateApiKeyUnique() {
        // Generate multiple keys and verify they are all different
        Set<String> keys = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            keys.add(MCPSettingsDialog.generateApiKey());
        }
        assertEquals("100 generated keys should all be unique", 100, keys.size());
    }

    @Test
    public void testGenerateApiKeyNotEmpty() {
        String key = MCPSettingsDialog.generateApiKey();
        assertNotNull("API key should not be null", key);
        assertFalse("API key should not be empty", key.isEmpty());
    }

    @Test
    public void testGenerateApiKeyLowercase() {
        String key = MCPSettingsDialog.generateApiKey();
        assertEquals("API key should be lowercase hex",
                key.toLowerCase(), key);
    }
}
