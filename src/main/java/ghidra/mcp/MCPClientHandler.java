package ghidra.mcp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class MCPClientHandler implements Runnable {
    private Socket clientSocket;
    private MCPContextProvider contextProvider;
    private Gson gson = new Gson();

    public MCPClientHandler(Socket socket, MCPContextProvider provider) {
        this.clientSocket = socket;
        this.contextProvider = provider;
    }

    @Override
    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)
        ) {
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                JsonObject request = gson.fromJson(inputLine, JsonObject.class);
                String method = request.get("method").getAsString();
                
                JsonObject response = new JsonObject();
                response.addProperty("id", request.get("id").getAsString());
                
                try {
                    switch (method) {
                        case "getContext":
                            Map<String, Object> context = contextProvider.getContext();
                            response.add("result", gson.toJsonTree(context));
                            break;
                            
                        case "getFunctionAt":
                            String address = request.get("params").getAsJsonObject().get("address").getAsString();
                            Map<String, Object> functionInfo = contextProvider.getFunctionAt(address);
                            response.add("result", gson.toJsonTree(functionInfo));
                            break;
                            
                        case "getDecompiledCode":
                            String funcAddr = request.get("params").getAsJsonObject().get("address").getAsString();
                            String decompiled = contextProvider.getDecompiledCode(funcAddr);
                            response.addProperty("result", decompiled);
                            break;
                            
                        case "analyzeBinaryForQuestion":
                            String question = request.get("params").getAsJsonObject().get("question").getAsString();
                            Map<String, Object> analysisResult = contextProvider.analyzeBinaryForQuestion(question);
                            response.add("result", gson.toJsonTree(analysisResult));
                            break;
                            
                        case "getAllFunctions":
                            Map<String, Object> allFunctions = contextProvider.getAllFunctions();
                            response.add("result", gson.toJsonTree(allFunctions));
                            break;
                            
                        case "getStrings":
                            Map<String, Object> strings = contextProvider.getStrings();
                            response.add("result", gson.toJsonTree(strings));
                            break;
                            
                        case "getImports":
                            Map<String, Object> imports = contextProvider.getImports();
                            response.add("result", gson.toJsonTree(imports));
                            break;
                            
                        case "getExports":
                            Map<String, Object> exports = contextProvider.getExports();
                            response.add("result", gson.toJsonTree(exports));
                            break;
                            
                        case "getMemoryMap":
                            Map<String, Object> memoryMap = contextProvider.getMemoryMap();
                            response.add("result", gson.toJsonTree(memoryMap));
                            break;

                        case "renameFunction":
                            String currentName = request.get("params").getAsJsonObject().get("currentName").getAsString();
                            String newFuncName = request.get("params").getAsJsonObject().get("newName").getAsString();
                            boolean funcRenamed = contextProvider.renameFunction(currentName, newFuncName);
                            response.addProperty("result", funcRenamed);
                            break;

                        case "renameData":
                            String dataAddr = request.get("params").getAsJsonObject().get("address").getAsString();
                            String newDataName = request.get("params").getAsJsonObject().get("newName").getAsString();
                            boolean dataRenamed = contextProvider.renameData(dataAddr, newDataName);
                            response.addProperty("result", dataRenamed);
                            break;

                        case "extractApiCallSequences":
                            String apiCallFuncAddr = request.get("params").getAsJsonObject().get("address").getAsString();
                            Map<String, Object> apiCallSequences = contextProvider.extractApiCallSequences(apiCallFuncAddr);
                            response.add("result", gson.toJsonTree(apiCallSequences));
                            break;

                        case "identifyUserInputSources":
                            Map<String, Object> inputSources = contextProvider.identifyUserInputSources();
                            response.add("result", gson.toJsonTree(inputSources));
                            break;

                        case "generateStructuredCallGraph":
                            String startFuncAddr = request.get("params").getAsJsonObject().get("address").getAsString();
                            int maxDepth = request.get("params").getAsJsonObject().get("maxDepth").getAsInt();
                            Map<String, Object> callGraph = contextProvider.generateStructuredCallGraph(startFuncAddr, maxDepth);
                            response.add("result", gson.toJsonTree(callGraph));
                            break;

                        case "identifyCryptographicPatterns":
                            Map<String, Object> cryptoPatterns = contextProvider.identifyCryptographicPatterns();
                            response.add("result", gson.toJsonTree(cryptoPatterns));
                            break;

                        case "findObfuscatedStrings":
                            Map<String, Object> obfuscatedStrings = contextProvider.findObfuscatedStrings();
                            response.add("result", gson.toJsonTree(obfuscatedStrings));
                            break;
                            
                        default:
                            response.addProperty("error", "Unknown method: " + method);
                    }
                } catch (Exception e) {
                    response.addProperty("error", e.getMessage());
                    e.printStackTrace();
                }
                
                out.println(gson.toJson(response));
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}