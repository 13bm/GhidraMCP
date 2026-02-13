package ghidra.mcp;

import static org.junit.Assert.*;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for MCPClientHandler's length-prefixed framing protocol and dispatch.
 *
 * These tests create a real TCP socket pair — one side acts as the "Go bridge"
 * client, the other is the MCPClientHandler under test. No Ghidra runtime is
 * needed because we use a minimal stub MCPContextProvider (the handler will
 * call contextProvider methods which may throw, but we test the framing and
 * dispatch routing, not the Ghidra API calls themselves).
 */
public class MCPClientHandlerTest {

    private ServerSocket serverSocket;
    private Socket clientSocket;   // our test acts as the "client"
    private Socket serverSideSocket;
    private ExecutorService executor;
    private Gson gson = new Gson();

    @Before
    public void setUp() throws Exception {
        serverSocket = new ServerSocket(0); // OS picks a free port
        executor = Executors.newSingleThreadExecutor();

        // Connect a client socket to the server socket
        int port = serverSocket.getLocalPort();
        Future<Socket> acceptFuture = executor.submit(() -> serverSocket.accept());
        clientSocket = new Socket("127.0.0.1", port);
        serverSideSocket = acceptFuture.get(5, TimeUnit.SECONDS);
    }

    @After
    public void tearDown() throws Exception {
        if (clientSocket != null) clientSocket.close();
        if (serverSideSocket != null) serverSideSocket.close();
        if (serverSocket != null) serverSocket.close();
        if (executor != null) executor.shutdownNow();
    }

    // ---- Framing helpers (mirror the protocol from the client side) ----

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
        assertTrue("Response length must be positive", length > 0);
        assertTrue("Response length must be under 50MB", length < 50 * 1024 * 1024);
        byte[] buf = new byte[length];
        dis.readFully(buf);
        String json = new String(buf, StandardCharsets.UTF_8);
        return gson.fromJson(json, JsonObject.class);
    }

    // ---- Tests ----

    /**
     * The simplest test: send a "ping" and verify we get {"result":"pong"}.
     * The ping handler doesn't touch MCPContextProvider at all, so this works
     * without any Ghidra runtime.
     */
    @Test
    public void testPingPong() throws Exception {
        // Start the handler on the server-side socket (no auth, null contextProvider is fine for ping)
        MCPClientHandler handler = new MCPClientHandler(serverSideSocket, null);

        Future<?> handlerFuture = executor.submit(handler);

        DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream dis = new DataInputStream(clientSocket.getInputStream());

        sendRequest(dos, "1", "ping", null);
        JsonObject resp = readResponse(dis);

        assertEquals("1", resp.get("id").getAsString());
        assertEquals("pong", resp.get("result").getAsString());

        // Close client to trigger clean exit of handler
        clientSocket.close();
        handlerFuture.get(5, TimeUnit.SECONDS);
    }

    /**
     * Verify that an unknown method returns an error response (not a crash).
     */
    @Test
    public void testUnknownMethodReturnsError() throws Exception {
        MCPClientHandler handler = new MCPClientHandler(serverSideSocket, null);
        Future<?> handlerFuture = executor.submit(handler);

        DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream dis = new DataInputStream(clientSocket.getInputStream());

        sendRequest(dos, "42", "totallyBogusMethod", null);
        JsonObject resp = readResponse(dis);

        assertEquals("42", resp.get("id").getAsString());
        assertTrue("Should have error field", resp.has("error"));
        assertTrue("Error should mention unknown method",
            resp.get("error").getAsString().contains("Unknown method"));

        clientSocket.close();
        handlerFuture.get(5, TimeUnit.SECONDS);
    }

    /**
     * Multiple sequential requests on the same connection should all get responses.
     */
    @Test
    public void testMultipleRequestsOnSameConnection() throws Exception {
        MCPClientHandler handler = new MCPClientHandler(serverSideSocket, null);
        Future<?> handlerFuture = executor.submit(handler);

        DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream dis = new DataInputStream(clientSocket.getInputStream());

        for (int i = 1; i <= 5; i++) {
            sendRequest(dos, String.valueOf(i), "ping", null);
            JsonObject resp = readResponse(dis);
            assertEquals(String.valueOf(i), resp.get("id").getAsString());
            assertEquals("pong", resp.get("result").getAsString());
        }

        clientSocket.close();
        handlerFuture.get(5, TimeUnit.SECONDS);
    }

    /**
     * Authentication flow: when auth is required, non-auth requests should be rejected,
     * and a correct API key should grant access.
     */
    @Test
    public void testAuthenticationRequired() throws Exception {
        MCPClientHandler handler = new MCPClientHandler(serverSideSocket, null);
        handler.setRequireAuthentication(true);
        handler.setApiKey("secret123");

        Future<?> handlerFuture = executor.submit(handler);

        DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream dis = new DataInputStream(clientSocket.getInputStream());

        // Try a ping before authenticating — should be rejected
        sendRequest(dos, "1", "ping", null);
        JsonObject resp1 = readResponse(dis);
        assertEquals("1", resp1.get("id").getAsString());
        assertTrue("Should require auth", resp1.has("error"));
        assertTrue(resp1.get("error").getAsString().contains("Authentication required"));

        // Authenticate with correct key
        JsonObject authParams = new JsonObject();
        authParams.addProperty("apiKey", "secret123");
        sendRequest(dos, "2", "authenticate", authParams);
        JsonObject resp2 = readResponse(dis);
        assertEquals("2", resp2.get("id").getAsString());
        assertTrue("Auth should succeed", resp2.get("result").getAsBoolean());

        // Now ping should work
        sendRequest(dos, "3", "ping", null);
        JsonObject resp3 = readResponse(dis);
        assertEquals("pong", resp3.get("result").getAsString());

        clientSocket.close();
        handlerFuture.get(5, TimeUnit.SECONDS);
    }

    /**
     * Authentication with wrong key should fail, and after 3 failed attempts
     * the connection should be terminated.
     */
    @Test
    public void testAuthenticationFailureAndLockout() throws Exception {
        MCPClientHandler handler = new MCPClientHandler(serverSideSocket, null);
        handler.setRequireAuthentication(true);
        handler.setApiKey("correctKey");

        Future<?> handlerFuture = executor.submit(handler);

        DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream dis = new DataInputStream(clientSocket.getInputStream());

        // Send 3 wrong keys
        for (int i = 1; i <= 3; i++) {
            JsonObject authParams = new JsonObject();
            authParams.addProperty("apiKey", "wrongKey" + i);
            sendRequest(dos, String.valueOf(i), "authenticate", authParams);
            JsonObject resp = readResponse(dis);
            assertTrue("Should have error", resp.has("error"));
        }

        // The 3rd failure should have closed the connection.
        // The handler should exit cleanly.
        handlerFuture.get(5, TimeUnit.SECONDS);
    }

    /**
     * Verify the response ID always matches the request ID.
     */
    @Test
    public void testResponseIdMatchesRequest() throws Exception {
        MCPClientHandler handler = new MCPClientHandler(serverSideSocket, null);
        Future<?> handlerFuture = executor.submit(handler);

        DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream dis = new DataInputStream(clientSocket.getInputStream());

        String[] ids = {"abc", "999", "test-id-with-dashes", "0"};
        for (String id : ids) {
            sendRequest(dos, id, "ping", null);
            JsonObject resp = readResponse(dis);
            assertEquals("Response ID must match request ID", id, resp.get("id").getAsString());
        }

        clientSocket.close();
        handlerFuture.get(5, TimeUnit.SECONDS);
    }

    /**
     * Verify that the handler exits cleanly when the client disconnects (EOF).
     */
    @Test
    public void testCleanDisconnect() throws Exception {
        MCPClientHandler handler = new MCPClientHandler(serverSideSocket, null);
        Future<?> handlerFuture = executor.submit(handler);

        // Immediately close client socket
        clientSocket.close();

        // Handler should exit without exception
        handlerFuture.get(5, TimeUnit.SECONDS);
    }
}
