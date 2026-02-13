package ghidra.mcp;

import static org.junit.Assert.*;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.*;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Full end-to-end integration tests for the GhidraMCP plugin.
 *
 * Extends Ghidra's {@link AbstractGhidraHeadedIntegrationTest}, which spins up
 * a real Ghidra environment with UI tool, program, and all services. The tests:
 *
 * 1. Build a synthetic x86 program with known functions
 * 2. Launch the MCP server plugin (which opens a TCP socket)
 * 3. Connect as a TCP client and send JSON-RPC commands
 * 4. Verify the responses AND the actual Ghidra program state
 *
 * Requires GHIDRA_INSTALL_DIR to be set and Xvfb on headless Linux CI.
 */
public class MCPServerIntegrationTest extends AbstractGhidraHeadedIntegrationTest {

    private TestEnv env;
    private PluginTool tool;
    private ProgramDB program;
    private Gson gson = new Gson();

    /** Port the MCP server will listen on. Matches the plugin default. */
    private static final int TEST_PORT = 8765;

    @Before
    public void setUp() throws Exception {
        env = new TestEnv();

        // Build a test program with known structure
        ProgramBuilder builder = new ProgramBuilder("TestBinary", ProgramBuilder._X86);
        builder.createMemory(".text", "0x00401000", 0x1000);
        // push ebp; mov ebp,esp; sub esp,0x10; leave; ret
        builder.setBytes("0x00401000", "55 8b ec 83 ec 10 c9 c3");
        builder.disassemble("0x00401000", 8);
        builder.createEmptyFunction("main", "0x00401000", 8, DataType.DEFAULT);

        // Second function for cross-reference / search tests
        builder.setBytes("0x00401100", "55 8b ec 5d c3");
        builder.disassemble("0x00401100", 5);
        builder.createEmptyFunction("helperFunc", "0x00401100", 5, DataType.DEFAULT);

        // A defined string for string listing tests
        builder.createMemory(".data", "0x00402000", 0x100);
        builder.setBytes("0x00402000", "48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21 00"); // "Hello, World!\0"

        program = builder.getProgram();
        builder.dispose();

        // Show tool with program and add the MCP server plugin
        tool = env.showTool(program);
        addPlugin(tool, MCPServerPlugin.class);

        // Wait for plugin init() which uses SwingUtilities.invokeLater
        waitForSwing();

        // Give the TCP listener thread a moment to bind and start accepting
        Thread.sleep(500);
    }

    @After
    public void tearDown() throws Exception {
        if (env != null) {
            env.dispose();
        }
        waitForSwing();
    }

    // =======================================================================
    // Wire protocol helpers
    // =======================================================================

    private Socket connect() throws IOException {
        return new Socket("127.0.0.1", TEST_PORT);
    }

    private void sendRequest(DataOutputStream dos, String id, String method, JsonObject params) throws IOException {
        JsonObject req = new JsonObject();
        req.addProperty("id", id);
        req.addProperty("method", method);
        if (params != null) {
            req.add("params", params);
        }
        byte[] payload = gson.toJson(req).getBytes(StandardCharsets.UTF_8);
        dos.writeInt(payload.length);
        dos.write(payload);
        dos.flush();
    }

    private JsonObject readResponse(DataInputStream dis) throws IOException {
        int length = dis.readInt();
        assertTrue("Response length must be positive, got " + length, length > 0);
        byte[] buf = new byte[length];
        dis.readFully(buf);
        return gson.fromJson(new String(buf, StandardCharsets.UTF_8), JsonObject.class);
    }

    private JsonObject rpc(String method, JsonObject params) throws IOException {
        try (Socket socket = connect()) {
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            sendRequest(dos, "1", method, params);
            return readResponse(dis);
        }
    }

    // =======================================================================
    // Connectivity tests
    // =======================================================================

    @Test
    public void testPing() throws Exception {
        JsonObject resp = rpc("ping", null);
        assertEquals("pong", resp.get("result").getAsString());
    }

    @Test
    public void testUnknownMethodReturnsError() throws Exception {
        JsonObject resp = rpc("completelyBogusMethod", null);
        assertTrue(resp.has("error"));
        assertTrue(resp.get("error").getAsString().contains("Unknown method"));
    }

    @Test
    public void testMultipleConnectionsSequential() throws Exception {
        // Each RPC call opens a new socket — verify the server handles multiple connections
        for (int i = 0; i < 5; i++) {
            JsonObject resp = rpc("ping", null);
            assertEquals("pong", resp.get("result").getAsString());
        }
    }

    // =======================================================================
    // Query tests — read-only operations on the synthetic program
    // =======================================================================

    @Test
    public void testGetContext() throws Exception {
        JsonObject resp = rpc("getContext", null);
        assertTrue(resp.has("result"));
        JsonObject result = resp.getAsJsonObject("result");
        // Should have program name
        assertTrue(result.has("name") || result.has("programName"));
    }

    @Test
    public void testGetAllFunctions() throws Exception {
        JsonObject resp = rpc("getAllFunctions", null);
        assertTrue(resp.has("result"));
        // Result should contain our two functions: main and helperFunc
        String resultStr = gson.toJson(resp.get("result"));
        assertTrue("Should contain 'main'", resultStr.contains("main"));
        assertTrue("Should contain 'helperFunc'", resultStr.contains("helperFunc"));
    }

    @Test
    public void testSearchFunctionsByName() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("query", "helper");
        JsonObject resp = rpc("searchFunctionsByName", params);
        assertTrue(resp.has("result"));
        String resultStr = gson.toJson(resp.get("result"));
        assertTrue("Should find helperFunc", resultStr.contains("helperFunc"));
        assertFalse("Should not find main", resultStr.contains("\"main\""));
    }

    @Test
    public void testGetFunctionByAddress() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00401000");
        JsonObject resp = rpc("getFunctionByAddress", params);
        assertTrue(resp.has("result"));
        String resultStr = gson.toJson(resp.get("result"));
        assertTrue("Should return main function", resultStr.contains("main"));
    }

    @Test
    public void testGetVariables() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("functionAddress", "0x00401000");
        JsonObject resp = rpc("getVariables", params);
        assertTrue(resp.has("result"));
        // May have empty variables for a simple stub, but should not error
        assertFalse("Should not have error", resp.has("error"));
    }

    @Test
    public void testGetMemoryMap() throws Exception {
        JsonObject resp = rpc("getMemoryMap", null);
        assertTrue(resp.has("result"));
        String resultStr = gson.toJson(resp.get("result"));
        assertTrue("Should contain .text segment", resultStr.contains(".text"));
        assertTrue("Should contain .data segment", resultStr.contains(".data"));
    }

    @Test
    public void testGetDecompiledCode() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00401000");
        JsonObject resp = rpc("getDecompiledCode", params);
        // Decompilation may or may not work in a minimal test program,
        // but the RPC should not crash
        assertTrue(resp.has("result") || resp.has("error"));
    }

    @Test
    public void testDisassembleFunction() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00401000");
        JsonObject resp = rpc("disassembleFunction", params);
        assertTrue(resp.has("result"));
        String resultStr = gson.toJson(resp.get("result"));
        // Should contain some assembly
        assertTrue("Should have disassembly output", resultStr.length() > 10);
    }

    @Test
    public void testGetStrings() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("offset", 0);
        params.addProperty("limit", 100);
        JsonObject resp = rpc("getStrings", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testListClasses() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("offset", 0);
        params.addProperty("limit", 100);
        JsonObject resp = rpc("listClasses", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testListNamespaces() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("offset", 0);
        params.addProperty("limit", 100);
        JsonObject resp = rpc("listNamespaces", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testGetImports() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("offset", 0);
        params.addProperty("limit", 100);
        JsonObject resp = rpc("getImports", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testGetExports() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("offset", 0);
        params.addProperty("limit", 100);
        JsonObject resp = rpc("getExports", params);
        assertTrue(resp.has("result"));
    }

    // =======================================================================
    // Mutation tests — modify the program via RPC and verify state
    // =======================================================================

    @Test
    public void testRenameFunctionByAddress() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00401000");
        params.addProperty("newName", "renamedMain");
        JsonObject resp = rpc("renameFunction", params);
        assertTrue(resp.has("result"));

        // Verify the program was actually modified
        waitForSwing();
        Address addr = program.getAddressFactory().getAddress("0x00401000");
        Function func = program.getFunctionManager().getFunctionAt(addr);
        assertNotNull("Function should still exist", func);
        assertEquals("renamedMain", func.getName());
    }

    @Test
    public void testRenameFunctionByName() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("currentName", "helperFunc");
        params.addProperty("newName", "myHelper");
        JsonObject resp = rpc("renameFunction", params);
        assertTrue(resp.has("result"));

        waitForSwing();
        Address addr = program.getAddressFactory().getAddress("0x00401100");
        Function func = program.getFunctionManager().getFunctionAt(addr);
        assertNotNull(func);
        assertEquals("myHelper", func.getName());
    }

    @Test
    public void testSetDecompilerComment() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00401000");
        params.addProperty("comment", "This is the entry point");
        JsonObject resp = rpc("setDecompilerComment", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testSetDisassemblyComment() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00401000");
        params.addProperty("comment", "Start of main");
        JsonObject resp = rpc("setDisassemblyComment", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testSetBookmarkAndGet() throws Exception {
        // Set a bookmark
        JsonObject setParams = new JsonObject();
        setParams.addProperty("address", "0x00401000");
        setParams.addProperty("type", "Note");
        setParams.addProperty("category", "TestCategory");
        setParams.addProperty("comment", "Test bookmark");
        JsonObject setResp = rpc("setBookmark", setParams);
        assertTrue(setResp.has("result"));

        // Get bookmarks at that address
        JsonObject getParams = new JsonObject();
        getParams.addProperty("address", "0x00401000");
        JsonObject getResp = rpc("getBookmarks", getParams);
        assertTrue(getResp.has("result"));
        String resultStr = gson.toJson(getResp.get("result"));
        assertTrue("Should contain our bookmark", resultStr.contains("TestCategory"));
    }

    @Test
    public void testRenameData() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00402000");
        params.addProperty("newName", "greeting_string");
        JsonObject resp = rpc("renameData", params);
        // May succeed or fail depending on data at that address, but should not crash
        assertTrue(resp.has("result") || resp.has("error"));
    }

    // =======================================================================
    // Cross-reference tests
    // =======================================================================

    @Test
    public void testGetXrefsTo() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00401000");
        params.addProperty("offset", 0);
        params.addProperty("limit", 100);
        JsonObject resp = rpc("getXrefsTo", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testGetXrefsFrom() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("address", "0x00401000");
        params.addProperty("offset", 0);
        params.addProperty("limit", 100);
        JsonObject resp = rpc("getXrefsFrom", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testGetFunctionXrefs() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("name", "main");
        params.addProperty("offset", 0);
        params.addProperty("limit", 100);
        JsonObject resp = rpc("getFunctionXrefs", params);
        assertTrue(resp.has("result"));
    }

    // =======================================================================
    // Advanced analysis tests — these may return empty results on a minimal
    // program, but should not crash or error
    // =======================================================================

    @Test
    public void testGetBasicBlocks() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("functionAddress", "0x00401000");
        JsonObject resp = rpc("getBasicBlocks", params);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testIdentifyUserInputSources() throws Exception {
        JsonObject resp = rpc("identifyUserInputSources", null);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testIdentifyCryptographicPatterns() throws Exception {
        JsonObject resp = rpc("identifyCryptographicPatterns", null);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testFindObfuscatedStrings() throws Exception {
        JsonObject resp = rpc("findObfuscatedStrings", null);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testExtractIOCs() throws Exception {
        JsonObject resp = rpc("extractIOCs", null);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testDetectAntiAnalysis() throws Exception {
        JsonObject resp = rpc("detectAntiAnalysis", null);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testDetectSecurityMitigations() throws Exception {
        JsonObject resp = rpc("detectSecurityMitigations", null);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testFindFormatStringVulns() throws Exception {
        JsonObject resp = rpc("findFormatStringVulns", null);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testListEquates() throws Exception {
        JsonObject resp = rpc("listEquates", null);
        assertTrue(resp.has("result"));
    }

    @Test
    public void testPEInfo() throws Exception {
        // Our test program is not a real PE, so this may return empty/error
        JsonObject resp = rpc("getPEInfo", null);
        assertTrue(resp.has("result") || resp.has("error"));
    }

    @Test
    public void testELFInfo() throws Exception {
        JsonObject resp = rpc("getELFInfo", null);
        assertTrue(resp.has("result") || resp.has("error"));
    }

    @Test
    public void testSearchBytes() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("pattern", "558BEC");
        params.addProperty("maxResults", 10);
        JsonObject resp = rpc("searchBytes", params);
        assertTrue(resp.has("result"));
        // Our test program has this pattern at 0x401000 and 0x401100
        String resultStr = gson.toJson(resp.get("result"));
        assertTrue("Should find the byte pattern", resultStr.contains("401000") || resultStr.contains("401100"));
    }
}
