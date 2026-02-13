package ghidra.mcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import ghidra.util.Msg;

/**
 * Handles a single MCP client connection using length-prefixed binary framing.
 *
 * Wire protocol: Each message is a 4-byte big-endian length prefix followed by
 * a UTF-8 JSON payload of exactly that many bytes. This replaces the old
 * newline-delimited protocol which corrupted messages containing newlines
 * (e.g., decompiled C code).
 */
public class MCPClientHandler implements Runnable {
    private final Socket clientSocket;
    private final MCPContextProvider contextProvider;
    private static final Gson GSON = new Gson();
    private boolean requireAuthentication = false;
    private String apiKey = "";
    private boolean authenticated = false;
    private static final int MAX_FAILED_AUTH_ATTEMPTS = 3;
    private int failedAuthAttempts = 0;

    /** Maximum message size: 50MB. Prevents OOM from malformed length prefixes. */
    private static final int MAX_MESSAGE_SIZE = 50 * 1024 * 1024;

    /** Maximum allowed value for pagination limit. */
    private static final int MAX_LIMIT = 10_000;

    /** Maximum allowed call graph depth. */
    private static final int MAX_CALL_GRAPH_DEPTH = 50;

    /** Maximum allowed emulation steps. */
    private static final int MAX_EMULATION_STEPS = 100_000;

    /** Maximum search results. */
    private static final int MAX_SEARCH_RESULTS = 10_000;

    public MCPClientHandler(Socket socket, MCPContextProvider provider) {
        this.clientSocket = socket;
        this.contextProvider = provider;
    }

    public void setRequireAuthentication(boolean requireAuthentication) {
        this.requireAuthentication = requireAuthentication;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    // ---- Length-prefixed framing helpers ----

    /**
     * Read a single length-prefixed message from the stream.
     * Format: 4-byte big-endian uint32 length + UTF-8 payload.
     */
    private String readMessage(DataInputStream dis) throws IOException {
        int length = dis.readInt(); // 4-byte big-endian signed int
        if (length <= 0 || length > MAX_MESSAGE_SIZE) {
            throw new IOException("Invalid message length: " + length);
        }
        byte[] buf = new byte[length];
        dis.readFully(buf);
        return new String(buf, StandardCharsets.UTF_8);
    }

    /**
     * Write a single length-prefixed message to the stream.
     * Format: 4-byte big-endian uint32 length + UTF-8 payload.
     */
    private void sendMessage(DataOutputStream dos, String json) throws IOException {
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(payload.length);
        dos.write(payload);
        dos.flush();
    }

    // ---- Parameter extraction helpers with type-safe casting ----

    /**
     * Safely extract an integer parameter with bounds clamping.
     */
    private int getIntParam(JsonObject params, String key, int defaultValue) {
        if (!params.has(key) || params.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return params.get(key).getAsInt();
        } catch (NumberFormatException | ClassCastException | IllegalStateException e) {
            return defaultValue;
        }
    }

    /**
     * Safely extract an integer parameter with bounds clamping.
     */
    private int getClampedIntParam(JsonObject params, String key, int defaultValue, int min, int max) {
        int value = getIntParam(params, key, defaultValue);
        return Math.max(min, Math.min(value, max));
    }

    /**
     * Safely extract a long parameter.
     */
    private long getLongParam(JsonObject params, String key, long defaultValue) {
        if (!params.has(key) || params.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return params.get(key).getAsLong();
        } catch (NumberFormatException | ClassCastException | IllegalStateException e) {
            return defaultValue;
        }
    }

    /**
     * Safely extract a string parameter.
     */
    private String getStringParam(JsonObject params, String key, String defaultValue) {
        if (!params.has(key) || params.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return params.get(key).getAsString();
        } catch (ClassCastException | IllegalStateException e) {
            return defaultValue;
        }
    }

    /**
     * Safely extract a required string parameter.
     * @throws IllegalArgumentException if the key is missing or not a string
     */
    private String getRequiredStringParam(JsonObject params, String key) {
        if (!params.has(key) || params.get(key).isJsonNull()) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        try {
            return params.get(key).getAsString();
        } catch (ClassCastException | IllegalStateException e) {
            throw new IllegalArgumentException("Parameter '" + key + "' must be a string");
        }
    }

    /**
     * Safely extract a boolean parameter.
     */
    private boolean getBoolParam(JsonObject params, String key, boolean defaultValue) {
        if (!params.has(key) || params.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return params.get(key).getAsBoolean();
        } catch (ClassCastException | IllegalStateException e) {
            return defaultValue;
        }
    }

    /**
     * Safely extract a JsonArray parameter, returning null if missing or wrong type.
     */
    private JsonArray getJsonArrayParam(JsonObject params, String key) {
        if (!params.has(key) || params.get(key).isJsonNull()) {
            return null;
        }
        try {
            return params.getAsJsonArray(key);
        } catch (ClassCastException e) {
            return null;
        }
    }

    /**
     * Constant-time comparison for API key authentication.
     * Prevents timing side-channel attacks.
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(
            a.getBytes(StandardCharsets.UTF_8),
            b.getBytes(StandardCharsets.UTF_8)
        );
    }

    // ---- Main handler loop ----

    @Override
    public void run() {
        try (
            DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream())
        ) {
            while (true) {
                String inputLine;
                try {
                    inputLine = readMessage(dis);
                } catch (EOFException e) {
                    // Client disconnected cleanly
                    break;
                } catch (SocketTimeoutException e) {
                    Msg.warn(this, "Client socket timed out — closing connection");
                    break;
                }

                // Parse the JSON-RPC request with safe field extraction
                JsonObject request;
                try {
                    request = GSON.fromJson(inputLine, JsonObject.class);
                } catch (JsonSyntaxException e) {
                    Msg.warn(this, "Received malformed JSON from client");
                    // Cannot extract an id, so use a placeholder
                    JsonObject errResponse = new JsonObject();
                    errResponse.addProperty("id", "unknown");
                    errResponse.addProperty("error", "Malformed JSON request");
                    sendMessage(dos, GSON.toJson(errResponse));
                    continue;
                }

                if (request == null) {
                    continue;
                }

                // Safely extract method and id with null checks
                JsonElement methodEl = request.get("method");
                JsonElement idEl = request.get("id");

                if (methodEl == null || methodEl.isJsonNull()) {
                    JsonObject errResponse = new JsonObject();
                    errResponse.addProperty("id", idEl != null ? idEl.getAsString() : "unknown");
                    errResponse.addProperty("error", "Missing 'method' field in request");
                    sendMessage(dos, GSON.toJson(errResponse));
                    continue;
                }

                if (idEl == null || idEl.isJsonNull()) {
                    JsonObject errResponse = new JsonObject();
                    errResponse.addProperty("id", "unknown");
                    errResponse.addProperty("error", "Missing 'id' field in request");
                    sendMessage(dos, GSON.toJson(errResponse));
                    continue;
                }

                String method;
                String requestId;
                try {
                    method = methodEl.getAsString();
                    requestId = idEl.getAsString();
                } catch (ClassCastException | IllegalStateException e) {
                    JsonObject errResponse = new JsonObject();
                    errResponse.addProperty("id", "unknown");
                    errResponse.addProperty("error", "Invalid 'method' or 'id' field type");
                    sendMessage(dos, GSON.toJson(errResponse));
                    continue;
                }

                JsonObject response = new JsonObject();
                response.addProperty("id", requestId);

                // Handle authentication if required
                if (requireAuthentication && !authenticated) {
                    if (method.equals("authenticate")) {
                        JsonElement paramsEl = request.get("params");
                        String providedKey = "";
                        if (paramsEl != null && paramsEl.isJsonObject()) {
                            JsonElement keyEl = paramsEl.getAsJsonObject().get("apiKey");
                            if (keyEl != null && !keyEl.isJsonNull()) {
                                try {
                                    providedKey = keyEl.getAsString();
                                } catch (ClassCastException | IllegalStateException e) {
                                    // leave as empty string
                                }
                            }
                        }
                        if (constantTimeEquals(apiKey, providedKey)) {
                            authenticated = true;
                            response.addProperty("result", true);
                            Msg.info(this, "Client authenticated successfully");
                        } else {
                            failedAuthAttempts++;
                            if (failedAuthAttempts >= MAX_FAILED_AUTH_ATTEMPTS) {
                                response.addProperty("error", "Max authentication attempts exceeded. Connection terminated.");
                                sendMessage(dos, GSON.toJson(response));
                                break; // Close connection
                            } else {
                                response.addProperty("error", "Authentication failed");
                            }
                        }
                        sendMessage(dos, GSON.toJson(response));
                        continue;
                    } else {
                        // Reject non-auth requests from unauthenticated clients
                        response.addProperty("error", "Authentication required");
                        sendMessage(dos, GSON.toJson(response));
                        continue;
                    }
                }

                try {
                    JsonObject params;
                    if (request.has("params") && request.get("params").isJsonObject()) {
                        params = request.get("params").getAsJsonObject();
                    } else {
                        params = new JsonObject();
                    }
                    dispatchMethod(method, params, response);
                } catch (IllegalArgumentException e) {
                    // Parameter validation errors — safe to return to client
                    Msg.warn(this, "Invalid request parameters: " + e.getMessage());
                    response.addProperty("error", e.getMessage());
                } catch (Exception e) {
                    // Internal errors — log full details, return generic message
                    Msg.error(this, "Error processing request '" + method + "': " + e.getMessage(), e);
                    response.addProperty("error", "Internal error processing request");
                }

                sendMessage(dos, GSON.toJson(response));
            }
        } catch (SocketTimeoutException e) {
            Msg.info(this, "Client connection timed out");
        } catch (IOException e) {
            Msg.error(this, "Client handler error: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
                Msg.info(this, "Client connection closed");
            } catch (IOException e) {
                Msg.error(this, "Error closing client socket: " + e.getMessage());
            }
        }
    }

    /**
     * Dispatch an RPC method call to the appropriate handler.
     * All parameter extraction uses type-safe helpers with proper casting.
     */
    private void dispatchMethod(String method, JsonObject params, JsonObject response) {
        switch (method) {

            // ===== Existing query methods =====

            case "getContext": {
                Map<String, Object> context = contextProvider.getContext();
                response.add("result", GSON.toJsonTree(context));
                break;
            }

            case "getDecompiledCode": {
                String funcAddr = getRequiredStringParam(params, "address");
                String decompiled = contextProvider.getDecompiledCode(funcAddr);
                response.addProperty("result", decompiled);
                break;
            }

            case "getAllFunctions": {
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> allFunctions = contextProvider.getAllFunctions(offset, limit);
                response.add("result", GSON.toJsonTree(allFunctions));
                break;
            }

            case "getStrings": {
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                String filter = getStringParam(params, "filter", null);
                Map<String, Object> strings = contextProvider.getStrings(offset, limit, filter);
                response.add("result", GSON.toJsonTree(strings));
                break;
            }

            case "getImports": {
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> imports = contextProvider.getImports(offset, limit);
                response.add("result", GSON.toJsonTree(imports));
                break;
            }

            case "getExports": {
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> exports = contextProvider.getExports(offset, limit);
                response.add("result", GSON.toJsonTree(exports));
                break;
            }

            case "getMemoryMap": {
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> memoryMap = contextProvider.getMemoryMap(offset, limit);
                response.add("result", GSON.toJsonTree(memoryMap));
                break;
            }

            case "getVariables": {
                String getVarsFuncAddr = getRequiredStringParam(params, "functionAddress");
                Map<String, Object> variables = contextProvider.getVariables(getVarsFuncAddr);
                response.add("result", GSON.toJsonTree(variables));
                break;
            }

            // ===== Existing mutation methods =====

            case "renameFunction": {
                if (params.has("address")) {
                    // Rename by address
                    String funcAddress = getRequiredStringParam(params, "address");
                    String newFuncName = getRequiredStringParam(params, "newName");
                    Map<String, Object> funcRenameResult = contextProvider.renameFunction(funcAddress, newFuncName, true);
                    response.add("result", GSON.toJsonTree(funcRenameResult));
                } else {
                    // Rename by name
                    String currentName = getRequiredStringParam(params, "currentName");
                    String newFuncName = getRequiredStringParam(params, "newName");
                    Map<String, Object> funcRenameResult = contextProvider.renameFunction(currentName, newFuncName, false);
                    response.add("result", GSON.toJsonTree(funcRenameResult));
                }
                break;
            }

            case "renameData": {
                String dataAddr = getRequiredStringParam(params, "address");
                String newDataName = getRequiredStringParam(params, "newName");
                Map<String, Object> dataOptions = null;
                if (params.has("options") && params.get("options").isJsonObject()) {
                    dataOptions = GSON.fromJson(
                        params.get("options"),
                        new TypeToken<Map<String, Object>>(){}.getType()
                    );
                }
                Map<String, Object> dataRenameResult = contextProvider.renameData(dataAddr, newDataName, dataOptions);
                response.add("result", GSON.toJsonTree(dataRenameResult));
                break;
            }

            case "renameVariable": {
                String varFuncAddr = getRequiredStringParam(params, "functionAddress");
                String oldVarName = getRequiredStringParam(params, "oldName");
                String newVarName = getRequiredStringParam(params, "newName");
                boolean varRenamed = contextProvider.renameVariable(varFuncAddr, oldVarName, newVarName);
                response.addProperty("result", varRenamed);
                break;
            }

            // ===== Existing analysis methods =====

            case "extractApiCallSequences": {
                String apiCallFuncAddr = getRequiredStringParam(params, "address");
                Map<String, Object> apiCallSequences = contextProvider.extractApiCallSequences(apiCallFuncAddr);
                response.add("result", GSON.toJsonTree(apiCallSequences));
                break;
            }

            case "identifyUserInputSources": {
                Map<String, Object> inputSources = contextProvider.identifyUserInputSources();
                response.add("result", GSON.toJsonTree(inputSources));
                break;
            }

            case "generateStructuredCallGraph": {
                String startFuncAddr = getRequiredStringParam(params, "address");
                int maxDepth = getClampedIntParam(params, "maxDepth", 5, 1, MAX_CALL_GRAPH_DEPTH);
                Map<String, Object> callGraph = contextProvider.generateStructuredCallGraph(startFuncAddr, maxDepth);
                response.add("result", GSON.toJsonTree(callGraph));
                break;
            }

            case "identifyCryptographicPatterns": {
                Map<String, Object> cryptoPatterns = contextProvider.identifyCryptographicPatterns();
                response.add("result", GSON.toJsonTree(cryptoPatterns));
                break;
            }

            case "findObfuscatedStrings": {
                Map<String, Object> obfuscatedStrings = contextProvider.findObfuscatedStrings();
                response.add("result", GSON.toJsonTree(obfuscatedStrings));
                break;
            }

            // ===== Phase 2: Query methods =====

            case "listClasses": {
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> classes = contextProvider.listClasses(offset, limit);
                response.add("result", GSON.toJsonTree(classes));
                break;
            }

            case "listNamespaces": {
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> namespaces = contextProvider.listNamespaces(offset, limit);
                response.add("result", GSON.toJsonTree(namespaces));
                break;
            }

            case "listDataItems": {
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> dataItems = contextProvider.listDataItems(offset, limit);
                response.add("result", GSON.toJsonTree(dataItems));
                break;
            }

            case "searchFunctionsByName": {
                String query = getRequiredStringParam(params, "query");
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> searchResults = contextProvider.searchFunctionsByName(query, offset, limit);
                response.add("result", GSON.toJsonTree(searchResults));
                break;
            }

            case "decompileFunctionByName": {
                String funcName = getRequiredStringParam(params, "name");
                Map<String, Object> decompResult = contextProvider.decompileFunctionByName(funcName);
                response.add("result", GSON.toJsonTree(decompResult));
                break;
            }

            case "disassembleFunction": {
                String disasmAddr = getRequiredStringParam(params, "address");
                Map<String, Object> disasmResult = contextProvider.disassembleFunction(disasmAddr);
                response.add("result", GSON.toJsonTree(disasmResult));
                break;
            }

            case "getFunctionByAddress": {
                String funcByAddrStr = getRequiredStringParam(params, "address");
                Map<String, Object> funcByAddr = contextProvider.getFunctionByAddress(funcByAddrStr);
                response.add("result", GSON.toJsonTree(funcByAddr));
                break;
            }

            case "getCurrentAddress": {
                Map<String, Object> currentAddr = contextProvider.getCurrentAddress();
                response.add("result", GSON.toJsonTree(currentAddr));
                break;
            }

            case "getCurrentFunction": {
                Map<String, Object> currentFunc = contextProvider.getCurrentFunction();
                response.add("result", GSON.toJsonTree(currentFunc));
                break;
            }

            // ===== Phase 2: Cross-reference methods =====

            case "getXrefsTo": {
                String xrefToAddr = getRequiredStringParam(params, "address");
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> xrefsTo = contextProvider.getXrefsTo(xrefToAddr, offset, limit);
                response.add("result", GSON.toJsonTree(xrefsTo));
                break;
            }

            case "getXrefsFrom": {
                String xrefFromAddr = getRequiredStringParam(params, "address");
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> xrefsFrom = contextProvider.getXrefsFrom(xrefFromAddr, offset, limit);
                response.add("result", GSON.toJsonTree(xrefsFrom));
                break;
            }

            case "getFunctionXrefs": {
                String xrefFuncName = getRequiredStringParam(params, "name");
                int offset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = getClampedIntParam(params, "limit", 100, 1, MAX_LIMIT);
                Map<String, Object> funcXrefs = contextProvider.getFunctionXrefs(xrefFuncName, offset, limit);
                response.add("result", GSON.toJsonTree(funcXrefs));
                break;
            }

            // ===== Phase 2: Comment methods =====

            case "setDecompilerComment": {
                String commentAddr = getRequiredStringParam(params, "address");
                String comment = getRequiredStringParam(params, "comment");
                Map<String, Object> commentResult = contextProvider.setDecompilerComment(commentAddr, comment);
                response.add("result", GSON.toJsonTree(commentResult));
                break;
            }

            case "setDisassemblyComment": {
                String disasmCommentAddr = getRequiredStringParam(params, "address");
                String disasmComment = getRequiredStringParam(params, "comment");
                Map<String, Object> disasmCommentResult = contextProvider.setDisassemblyComment(disasmCommentAddr, disasmComment);
                response.add("result", GSON.toJsonTree(disasmCommentResult));
                break;
            }

            // ===== Phase 2: Type system / prototype methods =====

            case "setFunctionPrototype": {
                String protoAddr = getRequiredStringParam(params, "functionAddress");
                String prototype = getRequiredStringParam(params, "prototype");
                Map<String, Object> protoResult = contextProvider.setFunctionPrototype(protoAddr, prototype);
                response.add("result", GSON.toJsonTree(protoResult));
                break;
            }

            case "setLocalVariableType": {
                String varTypeAddr = getRequiredStringParam(params, "functionAddress");
                String varTypeName = getRequiredStringParam(params, "variableName");
                String newType = getRequiredStringParam(params, "newType");
                Map<String, Object> varTypeResult = contextProvider.setLocalVariableType(varTypeAddr, varTypeName, newType);
                response.add("result", GSON.toJsonTree(varTypeResult));
                break;
            }

            // ===== Phase 2: Bookmark methods =====

            case "setBookmark": {
                String bmAddr = getRequiredStringParam(params, "address");
                String bmType = getStringParam(params, "type", "Note");
                String bmCategory = getStringParam(params, "category", "");
                String bmComment = getStringParam(params, "comment", "");
                Map<String, Object> bmResult = contextProvider.setBookmark(bmAddr, bmType, bmCategory, bmComment);
                response.add("result", GSON.toJsonTree(bmResult));
                break;
            }

            case "getBookmarks": {
                String bmGetAddr = getStringParam(params, "address", null);
                Map<String, Object> bookmarks = contextProvider.getBookmarks(bmGetAddr);
                response.add("result", GSON.toJsonTree(bookmarks));
                break;
            }

            case "removeBookmark": {
                String bmRemoveAddr = getRequiredStringParam(params, "address");
                String bmRemoveType = getRequiredStringParam(params, "type");
                String bmRemoveCategory = getRequiredStringParam(params, "category");
                Map<String, Object> bmRemoveResult = contextProvider.removeBookmark(bmRemoveAddr, bmRemoveType, bmRemoveCategory);
                response.add("result", GSON.toJsonTree(bmRemoveResult));
                break;
            }

            // ===== Phase 2: Equate methods =====

            case "setEquate": {
                String eqAddr = getRequiredStringParam(params, "address");
                int eqOpIndex = getClampedIntParam(params, "operandIndex", 0, 0, 16);
                String eqName = getRequiredStringParam(params, "name");
                long eqValue = getLongParam(params, "value", 0L);
                Map<String, Object> eqResult = contextProvider.setEquate(eqAddr, eqOpIndex, eqName, eqValue);
                response.add("result", GSON.toJsonTree(eqResult));
                break;
            }

            case "listEquates": {
                Map<String, Object> equates = contextProvider.listEquates();
                response.add("result", GSON.toJsonTree(equates));
                break;
            }

            // ===== Phase 2: Structure / enum creation =====

            case "createStructure": {
                String structName = getRequiredStringParam(params, "name");
                JsonArray fieldsArray = getJsonArrayParam(params, "fields");
                if (fieldsArray == null) {
                    throw new IllegalArgumentException("Missing required parameter: fields (must be a JSON array)");
                }
                List<Map<String, Object>> fields = new ArrayList<>();
                for (JsonElement el : fieldsArray) {
                    Map<String, Object> field = GSON.fromJson(el, new TypeToken<Map<String, Object>>(){}.getType());
                    fields.add(field);
                }
                Map<String, Object> structResult = contextProvider.createStructure(structName, fields);
                response.add("result", GSON.toJsonTree(structResult));
                break;
            }

            // ===== Structure CRUD =====

            case "getStructure": {
                String sName = getRequiredStringParam(params, "name");
                Map<String, Object> sResult = contextProvider.getStructure(sName);
                response.add("result", GSON.toJsonTree(sResult));
                break;
            }

            case "listStructures": {
                int lsOffset = getClampedIntParam(params, "offset", 0, 0, Integer.MAX_VALUE);
                int lsLimit = getClampedIntParam(params, "limit", 100, 1, 10000);
                Map<String, Object> lsResult = contextProvider.listStructures(lsOffset, lsLimit);
                response.add("result", GSON.toJsonTree(lsResult));
                break;
            }

            case "editStructure": {
                String esName = getRequiredStringParam(params, "name");
                JsonArray opsArray = getJsonArrayParam(params, "operations");
                if (opsArray == null) {
                    throw new IllegalArgumentException("Missing required parameter: operations (must be a JSON array)");
                }
                List<Map<String, Object>> ops = new ArrayList<>();
                for (JsonElement el : opsArray) {
                    Map<String, Object> op = GSON.fromJson(el, new TypeToken<Map<String, Object>>(){}.getType());
                    ops.add(op);
                }
                Map<String, Object> esResult = contextProvider.editStructure(esName, ops);
                response.add("result", GSON.toJsonTree(esResult));
                break;
            }

            case "renameStructure": {
                String rsCurrent = getRequiredStringParam(params, "currentName");
                String rsNew = getRequiredStringParam(params, "newName");
                Map<String, Object> rsResult = contextProvider.renameStructure(rsCurrent, rsNew);
                response.add("result", GSON.toJsonTree(rsResult));
                break;
            }

            case "deleteStructure": {
                String dsName = getRequiredStringParam(params, "name");
                Map<String, Object> dsResult = contextProvider.deleteStructure(dsName);
                response.add("result", GSON.toJsonTree(dsResult));
                break;
            }

            // ===== Async decompilation =====

            case "decompileFunctionAsync": {
                String asyncAddr = getRequiredStringParam(params, "address");
                Map<String, Object> asyncResult = contextProvider.decompileFunctionAsync(asyncAddr);
                response.add("result", GSON.toJsonTree(asyncResult));
                break;
            }

            case "getDecompileResult": {
                String taskId = getRequiredStringParam(params, "taskId");
                Map<String, Object> drResult = contextProvider.getDecompileResult(taskId);
                response.add("result", GSON.toJsonTree(drResult));
                break;
            }

            case "createEnum": {
                String enumName = getRequiredStringParam(params, "name");
                int enumSize = getClampedIntParam(params, "size", 4, 1, 8);
                JsonElement valuesEl = params.get("values");
                if (valuesEl == null || valuesEl.isJsonNull()) {
                    throw new IllegalArgumentException("Missing required parameter: values");
                }
                Map<String, Long> enumValues = GSON.fromJson(
                    valuesEl, new TypeToken<Map<String, Long>>(){}.getType()
                );
                Map<String, Object> enumResult = contextProvider.createEnum(enumName, enumSize, enumValues);
                response.add("result", GSON.toJsonTree(enumResult));
                break;
            }

            // ===== Phase 2: Data type application =====

            case "applyDataType": {
                String applyAddr = getRequiredStringParam(params, "address");
                String applyTypeName = getRequiredStringParam(params, "typeName");
                Map<String, Object> applyResult = contextProvider.applyDataType(applyAddr, applyTypeName);
                response.add("result", GSON.toJsonTree(applyResult));
                break;
            }

            // ===== Phase 2: Patch bytes =====

            case "patchBytes": {
                String patchAddr = getRequiredStringParam(params, "address");
                String hexBytes = getRequiredStringParam(params, "hexBytes");
                Map<String, Object> patchResult = contextProvider.patchBytes(patchAddr, hexBytes);
                response.add("result", GSON.toJsonTree(patchResult));
                break;
            }

            // ===== Phase 2: Basic blocks / CFG =====

            case "getBasicBlocks": {
                String bbAddr = getRequiredStringParam(params, "functionAddress");
                Map<String, Object> basicBlocks = contextProvider.getBasicBlocks(bbAddr);
                response.add("result", GSON.toJsonTree(basicBlocks));
                break;
            }

            // ===== Malware analysis tools =====

            case "searchBytes": {
                String searchPattern = getRequiredStringParam(params, "pattern");
                String searchMask = getStringParam(params, "mask", null);
                String searchStart = getStringParam(params, "startAddress", null);
                int searchMax = getClampedIntParam(params, "maxResults", 100, 1, MAX_SEARCH_RESULTS);
                Map<String, Object> searchResult = contextProvider.searchBytes(searchPattern, searchMask, searchStart, searchMax);
                response.add("result", GSON.toJsonTree(searchResult));
                break;
            }

            case "emulateFunction": {
                String emuAddr = getRequiredStringParam(params, "address");
                List<Long> emuArgs = new ArrayList<>();
                JsonArray argsArray = getJsonArrayParam(params, "args");
                if (argsArray != null) {
                    for (JsonElement el : argsArray) {
                        try {
                            emuArgs.add(el.getAsLong());
                        } catch (NumberFormatException | ClassCastException | IllegalStateException e) {
                            throw new IllegalArgumentException("Invalid argument in 'args' array: must be numeric");
                        }
                    }
                }
                int emuMaxSteps = getClampedIntParam(params, "maxSteps", 10000, 1, MAX_EMULATION_STEPS);
                Map<String, Object> emuResult = contextProvider.emulateFunction(emuAddr, emuArgs, emuMaxSteps);
                response.add("result", GSON.toJsonTree(emuResult));
                break;
            }

            case "extractIOCs": {
                Map<String, Object> iocs = contextProvider.extractIOCs();
                response.add("result", GSON.toJsonTree(iocs));
                break;
            }

            case "findDynamicAPIResolution": {
                Map<String, Object> dynApi = contextProvider.findDynamicAPIResolution();
                response.add("result", GSON.toJsonTree(dynApi));
                break;
            }

            case "detectAntiAnalysis": {
                Map<String, Object> antiAnalysis = contextProvider.detectAntiAnalysis();
                response.add("result", GSON.toJsonTree(antiAnalysis));
                break;
            }

            case "addExternalFunction": {
                String extLibrary = getRequiredStringParam(params, "library");
                String extFuncName = getRequiredStringParam(params, "functionName");
                String extAddr = getRequiredStringParam(params, "address");
                Map<String, Object> extResult = contextProvider.addExternalFunction(extLibrary, extFuncName, extAddr);
                response.add("result", GSON.toJsonTree(extResult));
                break;
            }

            case "getPEInfo": {
                Map<String, Object> peInfo = contextProvider.getPEInfo();
                response.add("result", GSON.toJsonTree(peInfo));
                break;
            }

            case "getELFInfo": {
                Map<String, Object> elfInfo = contextProvider.getELFInfo();
                response.add("result", GSON.toJsonTree(elfInfo));
                break;
            }

            // ===== IoT / embedded security tools =====

            case "setImageBase": {
                String newBase = getRequiredStringParam(params, "newBaseAddress");
                Map<String, Object> rebaseResult = contextProvider.setImageBase(newBase);
                response.add("result", GSON.toJsonTree(rebaseResult));
                break;
            }

            case "createMemoryBlock": {
                String blockName = getRequiredStringParam(params, "name");
                String blockAddr = getRequiredStringParam(params, "address");
                long blockSize = getLongParam(params, "size", 0L);
                if (blockSize <= 0) {
                    throw new IllegalArgumentException("Parameter 'size' must be a positive number");
                }
                String blockPerms = getStringParam(params, "permissions", "r--");
                boolean blockOverlay = getBoolParam(params, "isOverlay", false);
                Map<String, Object> blockResult = contextProvider.createMemoryBlock(blockName, blockAddr, blockSize, blockPerms, blockOverlay);
                response.add("result", GSON.toJsonTree(blockResult));
                break;
            }

            case "detectSecurityMitigations": {
                Map<String, Object> mitigations = contextProvider.detectSecurityMitigations();
                response.add("result", GSON.toJsonTree(mitigations));
                break;
            }

            case "findFormatStringVulns": {
                Map<String, Object> fmtVulns = contextProvider.findFormatStringVulns();
                response.add("result", GSON.toJsonTree(fmtVulns));
                break;
            }

            case "findROPGadgets": {
                int ropMaxLen = getClampedIntParam(params, "maxLength", 6, 1, 20);
                String[] ropTypes = null;
                JsonArray typesArray = getJsonArrayParam(params, "types");
                if (typesArray != null) {
                    ropTypes = new String[typesArray.size()];
                    for (int i = 0; i < typesArray.size(); i++) {
                        try {
                            ropTypes[i] = typesArray.get(i).getAsString();
                        } catch (ClassCastException | IllegalStateException e) {
                            throw new IllegalArgumentException("Invalid element in 'types' array: must be a string");
                        }
                    }
                }
                Map<String, Object> ropResult = contextProvider.findROPGadgets(ropMaxLen, ropTypes);
                response.add("result", GSON.toJsonTree(ropResult));
                break;
            }

            case "setCallingConvention": {
                String ccAddr = getRequiredStringParam(params, "functionAddress");
                String ccName = getRequiredStringParam(params, "convention");
                Map<String, Object> ccResult = contextProvider.setCallingConvention(ccAddr, ccName);
                response.add("result", GSON.toJsonTree(ccResult));
                break;
            }

            case "detectControlFlowFlattening": {
                String cffAddr = getRequiredStringParam(params, "functionAddress");
                Map<String, Object> cffResult = contextProvider.detectControlFlowFlattening(cffAddr);
                response.add("result", GSON.toJsonTree(cffResult));
                break;
            }

            case "setMemoryPermissions": {
                String permAddr = getRequiredStringParam(params, "address");
                boolean permRead = getBoolParam(params, "read", false);
                boolean permWrite = getBoolParam(params, "write", false);
                boolean permExec = getBoolParam(params, "execute", false);
                boolean permVolatile = getBoolParam(params, "isVolatile", false);
                Map<String, Object> permResult = contextProvider.setMemoryPermissions(permAddr, permRead, permWrite, permExec, permVolatile);
                response.add("result", GSON.toJsonTree(permResult));
                break;
            }

            case "markCodeCoverage": {
                JsonArray covArray = getJsonArrayParam(params, "addresses");
                if (covArray == null) {
                    throw new IllegalArgumentException("Missing required parameter: addresses (must be a JSON array)");
                }
                List<String> covAddresses = new ArrayList<>();
                for (JsonElement el : covArray) {
                    try {
                        covAddresses.add(el.getAsString());
                    } catch (ClassCastException | IllegalStateException e) {
                        throw new IllegalArgumentException("Invalid element in 'addresses' array: must be a string");
                    }
                }
                String covType = getStringParam(params, "bookmarkType", "CodeCoverage");
                Map<String, Object> covResult = contextProvider.markCodeCoverage(covAddresses, covType);
                response.add("result", GSON.toJsonTree(covResult));
                break;
            }

            // ===== Utility =====

            case "ping": {
                response.addProperty("result", "pong");
                break;
            }

            default:
                response.addProperty("error", "Unknown method: " + method);
        }
    }
}
