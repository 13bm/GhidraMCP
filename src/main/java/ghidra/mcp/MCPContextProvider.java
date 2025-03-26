package ghidra.mcp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

public class MCPContextProvider {
    private Program currentProgram;
    
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
    }
    
    public Map<String, Object> getContext() {
        Map<String, Object> context = new HashMap<>();
        
        if (currentProgram == null) {
            context.put("status", "no_program_loaded");
            return context;
        }
        
        context.put("status", "ok");
        context.put("program_name", currentProgram.getName());
        context.put("program_language", currentProgram.getLanguage().getLanguageID().getIdAsString());
        context.put("processor", currentProgram.getLanguage().getProcessor().toString());
        context.put("compiler", currentProgram.getCompiler());
        context.put("creation_date", currentProgram.getCreationDate().toString());
        context.put("executable_format", currentProgram.getExecutableFormat());
        context.put("executable_path", currentProgram.getExecutablePath());
        
        // Include some basic statistics
        FunctionManager functionManager = currentProgram.getFunctionManager();
        context.put("function_count", functionManager.getFunctionCount());
        
        return context;
    }
    
    public Map<String, Object> getFunctionAt(String addressStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        try {
            Address address = currentProgram.getAddressFactory().getAddress(addressStr);
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function function = functionManager.getFunctionAt(address);
            
            if (function == null) {
                result.put("error", "No function found at address " + addressStr);
                return result;
            }
            
            result.put("name", function.getName());
            result.put("entry_point", function.getEntryPoint().toString());
            result.put("size", function.getBody().getNumAddresses());
            
            // Get parameters
            List<Map<String, String>> params = new ArrayList<>();
            Variable[] parameters = function.getParameters();
            for (Variable param : parameters) {
                Map<String, String> paramMap = new HashMap<>();
                paramMap.put("name", param.getName());
                paramMap.put("dataType", param.getDataType().getName());
                params.add(paramMap);
            }
            result.put("parameters", params);
            
            // Get references to this function
            ReferenceManager refManager = currentProgram.getReferenceManager();
            List<String> callers = new ArrayList<>();
            Iterator<Reference> referencesTo = refManager.getReferencesTo(function.getEntryPoint());
            while (referencesTo.hasNext()) {
                Reference ref = referencesTo.next();
                Function callerFunction = functionManager.getFunctionContaining(ref.getFromAddress());
                if (callerFunction != null) {
                    callers.add(callerFunction.getName() + "@" + callerFunction.getEntryPoint());
                }
            }
            result.put("callers", callers);
            
            // Get called functions
            List<String> callees = new ArrayList<>();
            Set<Function> calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            for (Function calledFunc : calledFunctions) {
                callees.add(calledFunc.getName() + "@" + calledFunc.getEntryPoint());
            }
            result.put("calls", callees);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    public String getDecompiledCode(String addressStr) {
        if (currentProgram == null) {
            return "Error: No program loaded";
        }
        
        try {
            Address address = currentProgram.getAddressFactory().getAddress(addressStr);
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function function = functionManager.getFunctionAt(address);
            
            if (function == null) {
                return "Error: No function found at address " + addressStr;
            }
            
            DecompInterface decompInterface = new DecompInterface();
            decompInterface.openProgram(currentProgram);
            
            DecompileResults decompileResults = decompInterface.decompileFunction(function, 0, TaskMonitor.DUMMY);
            if (decompileResults.decompileCompleted()) {
                return decompileResults.getDecompiledFunction().getC();
            } else {
                return "Error: Decompilation failed: " + decompileResults.getErrorMessage();
            }
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    public Map<String, Object> getMemoryMap() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        List<Map<String, Object>> sections = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        
        for (MemoryBlock block : memory.getBlocks()) {
            Map<String, Object> section = new HashMap<>();
            section.put("name", block.getName());
            section.put("start", block.getStart().toString());
            section.put("end", block.getEnd().toString());
            section.put("size", block.getSize());
            section.put("readable", block.isRead());
            section.put("writable", block.isWrite());
            section.put("executable", block.isExecute());
            section.put("initialized", block.isInitialized());
            sections.add(section);
        }
        
        result.put("sections", sections);
        return result;
    }
    
    public Map<String, Object> getAllFunctions() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        List<Map<String, Object>> functions = new ArrayList<>();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        
        Iterator<Function> funcIter = functionManager.getFunctions(true);
        while (funcIter.hasNext()) {
            Function function = funcIter.next();
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("name", function.getName());
            functionInfo.put("entry_point", function.getEntryPoint().toString());
            functionInfo.put("size", function.getBody().getNumAddresses());
            functionInfo.put("is_external", function.isExternal());
            
            // Check if it's an entry point using the symbol table
            boolean isEntryPoint = false;
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(function.getEntryPoint());
            if (symbol != null) {
                isEntryPoint = symbol.isPrimary() && "ENTRY".equals(symbol.getSymbolType().toString());
            }
            functionInfo.put("is_entry_point", isEntryPoint);
            
            functionInfo.put("return_type", function.getReturnType().getName());
            functions.add(functionInfo);
        }
        
        result.put("functions", functions);
        result.put("count", functions.size());
        return result;
    }
    
    public Map<String, Object> getStrings() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        List<Map<String, Object>> strings = new ArrayList<>();
        int stringCount = 0;
        int maxStrings = 1000; // Limit the number of strings returned
        
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        while (dataIterator.hasNext() && stringCount < maxStrings) {
            Data data = dataIterator.next();
            if (data.hasStringValue()) {
                Map<String, Object> stringInfo = new HashMap<>();
                stringInfo.put("address", data.getAddress().toString());
                stringInfo.put("value", data.getValue().toString());
                stringInfo.put("length", data.getLength());
                stringInfo.put("data_type", data.getDataType().getName());
                strings.add(stringInfo);
                stringCount++;
            }
        }
        
        result.put("strings", strings);
        result.put("count", stringCount);
        return result;
    }
    
    public Map<String, Object> getImports() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        List<Map<String, Object>> imports = new ArrayList<>();
        ExternalManager externalManager = currentProgram.getExternalManager();
        
        for (String libraryName : externalManager.getExternalLibraryNames()) {
            Iterator<ExternalLocation> extLocIter = externalManager.getExternalLocations(libraryName);
            while (extLocIter.hasNext()) {
                ExternalLocation extLoc = extLocIter.next();
                Map<String, Object> importInfo = new HashMap<>();
                importInfo.put("name", extLoc.getLabel());
                importInfo.put("library", libraryName);
                importInfo.put("address", extLoc.getAddress() != null ? extLoc.getAddress().toString() : "null");
                importInfo.put("type", extLoc.getSymbol().getSymbolType().toString());
                imports.add(importInfo);
            }
        }
        
        result.put("imports", imports);
        result.put("count", imports.size());
        return result;
    }
    
    public Map<String, Object> getExports() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        List<Map<String, Object>> exports = new ArrayList<>();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
        
        while (entryPoints.hasNext()) {
            Address addr = entryPoints.next();
            Symbol symbol = symbolTable.getPrimarySymbol(addr);
            if (symbol != null) {
                Map<String, Object> exportInfo = new HashMap<>();
                exportInfo.put("name", symbol.getName());
                exportInfo.put("address", symbol.getAddress().toString());
                exportInfo.put("type", symbol.getSymbolType().toString());
                exports.add(exportInfo);
            }
        }
        
        result.put("exports", exports);
        result.put("count", exports.size());
        return result;
    }
    
    public Map<String, Object> analyzeBinaryForQuestion(String question) {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        try {
            // Prepare result container
            Map<String, Object> analysis = new HashMap<>();
            analysis.put("question", question);
            
            // 1. Basic program information
            analysis.put("program_name", currentProgram.getName());
            analysis.put("processor", currentProgram.getLanguage().getProcessor().toString());
            analysis.put("compiler", currentProgram.getCompiler());
            analysis.put("creation_date", currentProgram.getCreationDate().toString());
            
            // 2. Get important strings
            List<String> interestingStrings = extractInterestingStrings(question);
            analysis.put("relevant_strings", interestingStrings);
            
            // 3. Get entry points and main function
            Function mainFunction = findMainFunction();
            if (mainFunction != null) {
                analysis.put("main_function", getFunctionDetails(mainFunction));
                analysis.put("main_decompiled", getDecompiledCode(mainFunction.getEntryPoint().toString()));
            }
            
            // 4. Get imports/exports relevant to the question
            List<Map<String, String>> relevantImports = getRelevantImports(question);
            analysis.put("relevant_imports", relevantImports);
            
            // 5. Find functions relevant to the question
            List<Map<String, Object>> relevantFunctions = findRelevantFunctions(question);
            analysis.put("relevant_functions", relevantFunctions);
            
            // 6. Global analysis based on question type
            if (question.toLowerCase().contains("malware") || 
                question.toLowerCase().contains("vulnerability") ||
                question.toLowerCase().contains("exploit")) {
                analysis.put("security_analysis", performSecurityAnalysis());
            }
            
            // 7. Memory layout if relevant
            if (question.toLowerCase().contains("memory") || 
                question.toLowerCase().contains("layout") ||
                question.toLowerCase().contains("section")) {
                analysis.put("memory_sections", getMemorySections());
            }
            
            result.put("analysis", analysis);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
            e.printStackTrace();
        }
        
        return result;
    }

    public boolean renameFunction(String currentName, String newName) {
        if (currentProgram == null) {
            return false;
        }
        
        final boolean[] success = new boolean[1];
        success[0] = false;
        
        try {
            // Run on the Swing thread for thread safety
            SwingUtilities.invokeAndWait(() -> {
                // Start a transaction for proper undo/redo support
                int txId = currentProgram.startTransaction("Rename Function");
                
                try {
                    // Find the function by its name
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Iterator<Function> functions = functionManager.getFunctions(true);
                    Function targetFunction = null;
                    
                    while (functions.hasNext()) {
                        Function function = functions.next();
                        if (function.getName().equals(currentName)) {
                            targetFunction = function;
                            break;
                        }
                    }
                    
                    if (targetFunction != null) {
                        // Rename the function
                        targetFunction.setName(newName, SourceType.USER_DEFINED);
                        success[0] = true;
                    }
                } catch (Exception e) {
                    System.err.println("Error renaming function: " + e.getMessage());
                    e.printStackTrace();
                } finally {
                    // End the transaction, applying changes if successful
                    currentProgram.endTransaction(txId, success[0]);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            System.err.println("Error executing on Swing thread: " + e.getMessage());
            e.printStackTrace();
        }
        
        return success[0];
    }

    public boolean renameData(String addressStr, String newName) {
        if (currentProgram == null) {
            return false;
        }
        
        final boolean[] success = new boolean[1];
        success[0] = false;
        
        try {
            // Run on the Swing thread for thread safety
            SwingUtilities.invokeAndWait(() -> {
                // Start a transaction for proper undo/redo support
                int txId = currentProgram.startTransaction("Rename Data");
                
                try {
                    // Convert the address string to an Address object
                    Address address = currentProgram.getAddressFactory().getAddress(addressStr);
                    if (address == null) {
                        return; // Invalid address
                    }
                    
                    // Get the symbol table
                    SymbolTable symbolTable = currentProgram.getSymbolTable();
                    Symbol symbol = symbolTable.getPrimarySymbol(address);
                    
                    if (symbol != null) {
                        // Rename existing symbol
                        symbol.setName(newName, SourceType.USER_DEFINED);
                        success[0] = true;
                    } else {
                        // Create a new symbol with the specified name
                        Namespace namespace = currentProgram.getGlobalNamespace();
                        symbolTable.createLabel(address, newName, namespace, SourceType.USER_DEFINED);
                        success[0] = true;
                    }
                } catch (Exception e) {
                    System.err.println("Error renaming data: " + e.getMessage());
                    e.printStackTrace();
                } finally {
                    // End the transaction, applying changes if successful
                    currentProgram.endTransaction(txId, success[0]);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            System.err.println("Error executing on Swing thread: " + e.getMessage());
            e.printStackTrace();
        }
        
        return success[0];
    }

    public Map<String, Object> extractApiCallSequences(String functionAddress) {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        try {
            Address address = currentProgram.getAddressFactory().getAddress(functionAddress);
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function function = functionManager.getFunctionAt(address);
            
            if (function == null) {
                result.put("error", "No function found at address " + functionAddress);
                return result;
            }
            
            // Simply collect the API calls without attempting to categorize them
            List<Map<String, Object>> apiCalls = new ArrayList<>();
            Set<Function> calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            
            for (Function calledFunc : calledFunctions) {
                if (calledFunc.isExternal()) {
                    Map<String, Object> apiInfo = new HashMap<>();
                    apiInfo.put("name", calledFunc.getName());
                    apiInfo.put("library", calledFunc.getExternalLocation().getLibraryName());
                    
                    // Get call sites
                    List<String> callSites = new ArrayList<>();
                    ReferenceManager refManager = currentProgram.getReferenceManager();
                    Iterator<Reference> refs = refManager.getReferencesTo(calledFunc.getEntryPoint());
                    
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        if (function.getBody().contains(ref.getFromAddress())) {
                            callSites.add(ref.getFromAddress().toString());
                        }
                    }
                    
                    apiInfo.put("callSites", callSites);
                    apiCalls.add(apiInfo);
                }
            }
            
            result.put("function", function.getName());
            result.put("apiCalls", apiCalls);
            
            // Add decompiled code for Claude to analyze patterns
            String decompiled = getDecompiledCode(functionAddress);
            result.put("decompiled", decompiled);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    private Map<String, List<String>> categorizeSecurityRelatedAPIs(List<Map<String, Object>> apiCalls) {
        Map<String, List<String>> categories = new HashMap<>();
        categories.put("crypto", new ArrayList<>());
        categories.put("network", new ArrayList<>());
        categories.put("file", new ArrayList<>());
        categories.put("memory", new ArrayList<>());
        categories.put("process", new ArrayList<>());
        categories.put("registry", new ArrayList<>());
        
        // Define patterns for categorization
        Map<String, List<String>> patterns = new HashMap<>();
        patterns.put("crypto", Arrays.asList("crypt", "aes", "rsa", "sha", "md5", "hash", "ssl", "tls"));
        patterns.put("network", Arrays.asList("socket", "connect", "recv", "send", "http", "url", "dns", "ftp"));
        patterns.put("file", Arrays.asList("file", "open", "read", "write", "create", "delete"));
        patterns.put("memory", Arrays.asList("alloc", "malloc", "free", "heap", "memcpy", "memmove"));
        patterns.put("process", Arrays.asList("process", "thread", "create", "terminate", "exec", "spawn"));
        patterns.put("registry", Arrays.asList("registry", "reg", "hkey", "regopen", "regget", "regset"));
        
        for (Map<String, Object> apiCall : apiCalls) {
            String apiName = (String) apiCall.get("name");
            String apiNameLower = apiName.toLowerCase();
            
            for (Map.Entry<String, List<String>> entry : patterns.entrySet()) {
                String category = entry.getKey();
                List<String> categoryPatterns = entry.getValue();
                
                for (String pattern : categoryPatterns) {
                    if (apiNameLower.contains(pattern)) {
                        categories.get(category).add(apiName);
                        break;
                    }
                }
            }
        }
        
        return categories;
    }

    public Map<String, Object> identifyUserInputSources() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        // Just provide a list of common input-related functions and their references
        // Let Claude do the analysis
        List<Map<String, Object>> potentialInputFunctions = new ArrayList<>();
        
        try {
            String[] commonInputAPIs = {
                "scanf", "gets", "fgets", "read", "recv", "recvfrom", 
                "ReadFile", "ReadConsole", "GetAsyncKeyState",
                "GetCommandLine", "GetEnvironmentVariable"
            };
            
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            
            for (String apiName : commonInputAPIs) {
                SymbolIterator symbols = symbolTable.getSymbols(apiName);
                while (symbols.hasNext()) {
                    Symbol symbol = symbols.next();
                    
                    Map<String, Object> funcInfo = new HashMap<>();
                    funcInfo.put("name", apiName);
                    funcInfo.put("address", symbol.getAddress().toString());
                    
                    // Find references and calling functions
                    ReferenceManager refManager = currentProgram.getReferenceManager();
                    Iterator<Reference> refs = refManager.getReferencesTo(symbol.getAddress());
                    
                    List<Map<String, Object>> references = new ArrayList<>();
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        Map<String, Object> refInfo = new HashMap<>();
                        refInfo.put("address", ref.getFromAddress().toString());
                        
                        // Get function containing this reference
                        FunctionManager functionManager = currentProgram.getFunctionManager();
                        Function callerFunction = functionManager.getFunctionContaining(ref.getFromAddress());
                        
                        if (callerFunction != null) {
                            refInfo.put("function", callerFunction.getName());
                            refInfo.put("functionAddress", callerFunction.getEntryPoint().toString());
                        }
                        
                        references.add(refInfo);
                    }
                    
                    funcInfo.put("references", references);
                    potentialInputFunctions.add(funcInfo);
                }
            }
            
            result.put("potentialInputFunctions", potentialInputFunctions);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    public Map<String, Object> generateStructuredCallGraph(String startFunctionAddress, int maxDepth) {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        try {
            Address address = currentProgram.getAddressFactory().getAddress(startFunctionAddress);
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function startFunction = functionManager.getFunctionAt(address);
            
            if (startFunction == null) {
                result.put("error", "No function found at address " + startFunctionAddress);
                return result;
            }
            
            // Simpler approach - just get all called functions and their basic info
            Map<String, Object> callGraph = new HashMap<>();
            callGraph.put("name", startFunction.getName());
            callGraph.put("address", startFunction.getEntryPoint().toString());
            
            List<Map<String, Object>> calledFunctions = new ArrayList<>();
            try {
                Set<Function> functions = startFunction.getCalledFunctions(TaskMonitor.DUMMY);
                for (Function func : functions) {
                    Map<String, Object> funcInfo = new HashMap<>();
                    funcInfo.put("name", func.getName());
                    funcInfo.put("address", func.getEntryPoint().toString());
                    funcInfo.put("isExternal", func.isExternal());
                    
                    // For non-external functions, include decompiled code for Claude to analyze
                    if (!func.isExternal() && maxDepth > 1) {
                        funcInfo.put("decompiled", getDecompiledCode(func.getEntryPoint().toString()));
                    }
                    
                    calledFunctions.add(funcInfo);
                }
            } catch (Exception e) {
                callGraph.put("error", e.getMessage());
            }
            
            callGraph.put("calledFunctions", calledFunctions);
            callGraph.put("decompiled", getDecompiledCode(startFunctionAddress));
            
            result.put("callGraph", callGraph);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    private Map<String, Object> buildCallGraphNode(Function function, int depth, Set<String> visited) {
        Map<String, Object> node = new HashMap<>();
        
        String functionKey = function.getName() + "@" + function.getEntryPoint().toString();
        if (depth <= 0 || visited.contains(functionKey)) {
            return null;
        }
        
        visited.add(functionKey);
        
        node.put("name", function.getName());
        node.put("address", function.getEntryPoint().toString());
        node.put("isExternal", function.isExternal());
        
        if (!function.isExternal()) {
            List<Map<String, Object>> callees = new ArrayList<>();
            try {
                Set<Function> calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
                
                for (Function calledFunc : calledFunctions) {
                    Map<String, Object> calleeNode = buildCallGraphNode(calledFunc, depth - 1, visited);
                    if (calleeNode != null) {
                        callees.add(calleeNode);
                    }
                }
                
                node.put("calls", callees);
                
            } catch (Exception e) {
                // Handle any exception
                node.put("error", "Error retrieving called functions: " + e.getMessage());
            }
        }
        
        return node;
    }

    public Map<String, Object> identifyCryptographicPatterns() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        try {
            // Just provide decompiled code and constant data for functions
            // that might be crypto-related based on basic name matching
            
            List<Map<String, Object>> potentialCryptoFunctions = new ArrayList<>();
            
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Iterator<Function> functions = functionManager.getFunctions(true);
            
            // Look for crypto-related names (simplified approach)
            String[] cryptoPatterns = {
                "crypt", "aes", "des", "rsa", "sha", "md5", "hash", "cipher", "decrypt", "encrypt"
            };
            
            while (functions.hasNext()) {
                Function function = functions.next();
                
                if (function.isExternal()) {
                    continue;
                }
                
                String name = function.getName().toLowerCase();
                
                boolean isCryptoRelated = false;
                for (String pattern : cryptoPatterns) {
                    if (name.contains(pattern)) {
                        isCryptoRelated = true;
                        break;
                    }
                }
                
                if (isCryptoRelated) {
                    Map<String, Object> funcInfo = new HashMap<>();
                    funcInfo.put("name", function.getName());
                    funcInfo.put("address", function.getEntryPoint().toString());
                    funcInfo.put("matchedPattern", "Name contains crypto term");
                    funcInfo.put("decompiled", getDecompiledCode(function.getEntryPoint().toString()));
                    potentialCryptoFunctions.add(funcInfo);
                }
            }
            
            result.put("potentialCryptoFunctions", potentialCryptoFunctions);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    private void findCryptoConstantPatterns(List<Map<String, Object>> cryptoFunctions) {
        // AES S-box first few bytes
        byte[] aesSBoxPrefix = {(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b};
        
        // SHA-256 initial hash values
        long[] sha256InitialHash = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        
        // DES key permutation table bytes
        byte[] desPC1Prefix = {57, 49, 41, 33, 25, 17, 9};
        
        Memory memory = currentProgram.getMemory();
        
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && !block.isExecute()) {
                try {
                    findPatternInBlock(block, aesSBoxPrefix, "AES S-box", cryptoFunctions);
                    // Add other pattern searches
                } catch (Exception e) {
                    // Handle exception
                }
            }
        }
    }

    private void findPatternInBlock(MemoryBlock block, byte[] pattern, String description, 
                                List<Map<String, Object>> cryptoFunctions) throws Exception {
        byte[] blockData = new byte[(int)block.getSize()];
        block.getBytes(block.getStart(), blockData);
        
        // Simple pattern matching - in practice you'd use a more efficient algorithm
        for (int i = 0; i <= blockData.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (blockData[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                Map<String, Object> crypto = new HashMap<>();
                Address patternAddr = block.getStart().add(i);
                crypto.put("address", patternAddr.toString());
                crypto.put("type", "Constant");
                crypto.put("algorithm", description);
                crypto.put("confidence", "Medium");
                
                // Try to find functions referencing this address
                ReferenceManager refManager = currentProgram.getReferenceManager();
                Iterator<Reference> refs = refManager.getReferencesTo(patternAddr);
                List<String> referencingFunctions = new ArrayList<>();
                
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Function function = functionManager.getFunctionContaining(ref.getFromAddress());
                    
                    if (function != null) {
                        referencingFunctions.add(function.getName() + "@" + function.getEntryPoint());
                    }
                }
                
                crypto.put("referencingFunctions", referencingFunctions);
                cryptoFunctions.add(crypto);
            }
        }
    }

    private void findCryptoAPIUsage(List<Map<String, Object>> cryptoFunctions) {
        String[] cryptoAPIs = {
            "AES_", "EVP_", "SHA", "MD5", "Crypt", "BCrypt", "NCrypt", 
            "HMAC", "RSA_", "EC_", "BN_", "RAND_"
        };
        
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        
        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            String symbolName = symbol.getName();
            
            // Check if this symbol matches any of our crypto patterns
            boolean isCryptoAPI = false;
            for (String apiPrefix : cryptoAPIs) {
                if (symbolName.startsWith(apiPrefix)) {
                    isCryptoAPI = true;
                    break;
                }
            }
            
            if (isCryptoAPI) {
                Map<String, Object> crypto = new HashMap<>();
                crypto.put("address", symbol.getAddress().toString());
                crypto.put("type", "API");
                crypto.put("name", symbolName);
                
                // Determine likely algorithm
                String name = symbolName.toLowerCase();
                if (name.contains("aes")) {
                    crypto.put("algorithm", "AES");
                } else if (name.contains("sha")) {
                    crypto.put("algorithm", "SHA");
                } else if (name.contains("rsa")) {
                    crypto.put("algorithm", "RSA");
                } else if (name.contains("md5")) {
                    crypto.put("algorithm", "MD5");
                } else {
                    crypto.put("algorithm", "Unknown");
                }
                
                crypto.put("confidence", "High");
                cryptoFunctions.add(crypto);
            }
        }
    }

    private void findCryptoFunctionCharacteristics(List<Map<String, Object>> cryptoFunctions) {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> functions = functionManager.getFunctions(true);
        
        while (functions.hasNext()) {
            Function function = functions.next();
            
            // Skip external functions
            if (function.isExternal()) {
                continue;
            }
            
            // Skip very small or very large functions
            long size = function.getBody().getNumAddresses();
            if (size < 50 || size > 5000) {
                continue;
            }
            
            try {
                boolean hasCryptoCharacteristics = false;
                String reason = "";
                
                // Check for bit manipulation operations
                if (hasBitManipulationInstructions(function)) {
                    hasCryptoCharacteristics = true;
                    reason += "Contains bit manipulation operations; ";
                }
                
                // Check for byte substitution patterns
                if (hasByteSubstitutionPatterns(function)) {
                    hasCryptoCharacteristics = true;
                    reason += "Contains byte substitution patterns; ";
                }
                
                // Check for loop structures typical in crypto
                if (hasTypicalCryptoLoops(function)) {
                    hasCryptoCharacteristics = true;
                    reason += "Contains loop structures typical in crypto; ";
                }
                
                if (hasCryptoCharacteristics) {
                    Map<String, Object> crypto = new HashMap<>();
                    crypto.put("address", function.getEntryPoint().toString());
                    crypto.put("name", function.getName());
                    crypto.put("type", "Function");
                    crypto.put("algorithm", "Unknown");
                    crypto.put("confidence", "Low");
                    crypto.put("reason", reason);
                    cryptoFunctions.add(crypto);
                }
                
            } catch (Exception e) {
                // Skip this function if error
            }
        }
    }

    private boolean hasBitManipulationInstructions(Function function) {
        // This is a simplified implementation
        // In practice, you would need to analyze the instructions looking for:
        // - XOR, ROL, ROR, SHIFT operations that are common in crypto
        
        // Here we check if decompiled code contains these operations
        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
            
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC().toLowerCase();
                int bitOps = 0;
                
                if (code.contains(" ^ ")) bitOps++; // XOR
                if (code.contains(" << ")) bitOps++; // Left shift
                if (code.contains(" >> ")) bitOps++; // Right shift
                if (code.contains(" & ")) bitOps++; // AND
                if (code.contains(" | ")) bitOps++; // OR
                if (code.contains("rotate")) bitOps++; // Rotation
                
                // If many bit operations, likely crypto
                return bitOps >= 3;
            }
        } catch (Exception e) {
            // Ignore
        }
        
        return false;
    }

    private boolean hasByteSubstitutionPatterns(Function function) {
        // Look for array access patterns common in S-boxes
        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
            
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                
                // Look for array access patterns like: sbox[byte & 0xff]
                return code.contains("[") && code.contains("&") && 
                    (code.contains("0xff") || code.contains("0xf") || code.contains("255"));
            }
        } catch (Exception e) {
            // Ignore
        }
        
        return false;
    }

    private boolean hasTypicalCryptoLoops(Function function) {
        // Check for loop structures typical in crypto implementations
        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
            
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC().toLowerCase();
                
                // Check for multiple rounds/iterations - common in block ciphers
                if ((code.contains("round") || code.contains("iteration")) && 
                    (code.contains("for (") || code.contains("while ("))) {
                    return true;
                }
                
                // Check for magic numbers often used in crypto
                if (code.contains("0x67452301") || // MD5
                    code.contains("0xc3d2e1f0") || // SHA-1
                    code.contains("0x5a827999") || // SHA-1 constant
                    code.contains("0x6a09e667"))   // SHA-256
                {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        
        return false;
    }

    public Map<String, Object> findObfuscatedStrings() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        try {
            // Provide all strings and let Claude identify potentially obfuscated ones
            Map<String, Object> stringData = getStrings();
            result.put("allStrings", stringData);
            
            // Also provide some functions with string manipulation
            List<Map<String, Object>> stringManipulatingFunctions = new ArrayList<>();
            
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Iterator<Function> functions = functionManager.getFunctions(true);
            
            // Get some decompiled functions for Claude to analyze
            int maxFunctions = 10;
            int count = 0;
            
            while (functions.hasNext() && count < maxFunctions) {
                Function function = functions.next();
                
                if (function.isExternal()) {
                    continue;
                }
                
                String decompiled = getDecompiledCode(function.getEntryPoint().toString());
                if (decompiled.contains("char") && 
                    (decompiled.contains("=") || decompiled.contains("^") || 
                    decompiled.contains("+") || decompiled.contains("["))) {
                    
                    Map<String, Object> funcInfo = new HashMap<>();
                    funcInfo.put("name", function.getName());
                    funcInfo.put("address", function.getEntryPoint().toString());
                    funcInfo.put("decompiled", decompiled);
                    
                    stringManipulatingFunctions.add(funcInfo);
                    count++;
                }
            }
            
            result.put("stringManipulatingFunctions", stringManipulatingFunctions);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    private void findXorEncodedStrings(List<Map<String, Object>> obfuscatedStrings) {
        // Look for functions that may be decoding XOR-encoded strings
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> functions = functionManager.getFunctions(true);
        
        while (functions.hasNext()) {
            Function function = functions.next();
            
            // Skip external functions
            if (function.isExternal()) {
                continue;
            }
            
            try {
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(currentProgram);
                DecompileResults results = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
                
                if (results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC().toLowerCase();
                    
                    // Look for XOR operations with potential keys
                    if (code.contains(" ^ ") && 
                        (code.contains("char") || code.contains("byte"))) {
                        
                        Map<String, Object> obfuscatedString = new HashMap<>();
                        obfuscatedString.put("type", "XOR-encoded");
                        obfuscatedString.put("function", function.getName());
                        obfuscatedString.put("address", function.getEntryPoint().toString());
                        
                        // Try to determine XOR key if possible
                        String key = extractPotentialXorKey(code);
                        if (key != null) {
                            obfuscatedString.put("potentialKey", key);
                        }
                        
                        obfuscatedStrings.add(obfuscatedString);
                    }
                }
            } catch (Exception e) {
                // Skip this function if error
            }
        }
    }

    private String extractPotentialXorKey(String code) {
        // Simple pattern matching for XOR keys
        // In real implementation, this would be more sophisticated
        
        // Look for common patterns like: 
        // - c = encoded[i] ^ 0x37;
        // - c = encoded[i] ^ key;
        
        // Simple regex to find pattern
        Pattern pattern = Pattern.compile("[^a-zA-Z0-9_]([a-zA-Z0-9_]+)\\s*\\^\\s*(0x[0-9a-fA-F]+|[0-9]+)");
        Matcher matcher = pattern.matcher(code);
        
        if (matcher.find()) {
            return matcher.group(2);  // Return the potential key
        }
        
        return null;
    }

    private void findConstructedStrings(List<Map<String, Object>> obfuscatedStrings) {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> functions = functionManager.getFunctions(true);
        
        while (functions.hasNext()) {
            Function function = functions.next();
            
            // Skip external functions
            if (function.isExternal()) {
                continue;
            }
            
            try {
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(currentProgram);
                DecompileResults results = decompiler.decompileFunction(function, 0, TaskMonitor.DUMMY);
                
                if (results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC();
                    
                    // Look for string construction patterns
                    // For example: 
                    // - buffer[0] = 'H'; buffer[1] = 'e'; buffer[2] = 'l'; ...
                    // - string being built in a loop
                    
                    if ((code.contains("[") && code.contains("=") && code.contains("'")) ||
                        (code.contains("+=") && code.contains("\"") && 
                        (code.contains("for (") || code.contains("while (")))) {
                        
                        Map<String, Object> obfuscatedString = new HashMap<>();
                        obfuscatedString.put("type", "Character-by-character construction");
                        obfuscatedString.put("function", function.getName());
                        obfuscatedString.put("address", function.getEntryPoint().toString());
                        obfuscatedStrings.add(obfuscatedString);
                    }
                }
            } catch (Exception e) {
                // Skip this function if error
            }
        }
    }

    private List<String> extractInterestingStrings(String question) {
        List<String> results = new ArrayList<>();
        
        // Create a list of keywords from the question
        String[] keywords = question.toLowerCase().split("\\s+");
        Set<String> keywordSet = new HashSet<>();
        for (String word : keywords) {
            if (word.length() > 3) { // Only consider words longer than 3 chars
                keywordSet.add(word);
            }
        }
        
        // Extract program strings and filter by relevance
        int stringCount = 0;
        int maxStrings = 50; // Limit the number of strings returned
        
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        while (dataIterator.hasNext() && stringCount < maxStrings) {
            Data data = dataIterator.next();
            if (data.hasStringValue()) {
                String str = data.getValue().toString().toLowerCase();
                
                // Check if the string contains any keywords
                boolean isRelevant = false;
                for (String keyword : keywordSet) {
                    if (str.contains(keyword)) {
                        isRelevant = true;
                        break;
                    }
                }
                
                // Add printable ASCII strings that are relevant or important
                if (isRelevant || isPotentiallyImportantString(str)) {
                    results.add(data.getValue().toString());
                    stringCount++;
                }
            }
        }
        
        return results;
    }
    
    private boolean isPotentiallyImportantString(String str) {
        // Check for patterns that might indicate important strings
        return str.contains("http://") || 
               str.contains("https://") || 
               str.contains("file:") || 
               str.contains("error") || 
               str.contains("fail") || 
               str.contains("password") || 
               str.contains("username") || 
               str.contains("config") || 
               str.contains(".dll") || 
               str.contains(".exe") || 
               str.contains(".sys");
    }
    
    private Function findMainFunction() {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        
        // Look for common entry point function names
        String[] mainNames = {"main", "WinMain", "_main", "mainCRTStartup", "wmain"};
        
        Iterator<Function> funcIter = functionManager.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String name = func.getName();
            for (String mainName : mainNames) {
                if (name.equals(mainName)) {
                    return func;
                }
            }
        }
        
        // If no main found, try to find the entry point
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
        
        if (entryPoints.hasNext()) {
            Address entryAddr = entryPoints.next();
            return functionManager.getFunctionAt(entryAddr);
        }
        
        return null;
    }
    
    private Map<String, Object> getFunctionDetails(Function function) {
        Map<String, Object> details = new HashMap<>();
        
        details.put("name", function.getName());
        details.put("entry_point", function.getEntryPoint().toString());
        details.put("size", function.getBody().getNumAddresses());
        
        // Get parameters
        List<Map<String, String>> params = new ArrayList<>();
        Variable[] parameters = function.getParameters();
        for (Variable param : parameters) {
            Map<String, String> paramMap = new HashMap<>();
            paramMap.put("name", param.getName());
            paramMap.put("dataType", param.getDataType().getName());
            params.add(paramMap);
        }
        details.put("parameters", params);
        
        // Get called functions
        List<String> calledFunctions = new ArrayList<>();
        Set<Function> called = function.getCalledFunctions(TaskMonitor.DUMMY);
        for (Function f : called) {
            calledFunctions.add(f.getName() + "@" + f.getEntryPoint());
        }
        details.put("calls", calledFunctions);
        
        return details;
    }
    
    private List<Map<String, String>> getRelevantImports(String question) {
        List<Map<String, String>> relevantImports = new ArrayList<>();
        
        // Keywords from the question
        Set<String> keywords = new HashSet<>(Arrays.asList(question.toLowerCase().split("\\s+")));
        
        // Add common categories of interest
        if (question.toLowerCase().contains("network") || question.toLowerCase().contains("connect")) {
            keywords.addAll(Arrays.asList("socket", "connect", "recv", "send", "http", "dns", "url"));
        }
        
        if (question.toLowerCase().contains("file") || question.toLowerCase().contains("read") || 
            question.toLowerCase().contains("write")) {
            keywords.addAll(Arrays.asList("file", "open", "read", "write", "create", "delete"));
        }
        
        if (question.toLowerCase().contains("crypto") || question.toLowerCase().contains("encrypt")) {
            keywords.addAll(Arrays.asList("crypt", "aes", "rsa", "hash", "md5", "sha", "ssl", "tls"));
        }
        
        // Get external functions and check relevance
        ExternalManager externalManager = currentProgram.getExternalManager();
        
        for (String libraryName : externalManager.getExternalLibraryNames()) {
            Iterator<ExternalLocation> extLocIter = externalManager.getExternalLocations(libraryName);
            while (extLocIter.hasNext()) {
                ExternalLocation extLoc = extLocIter.next();
                String name = extLoc.getLabel().toLowerCase();
                String library = libraryName.toLowerCase();
                
                boolean isRelevant = false;
                for (String keyword : keywords) {
                    if (keyword.length() > 3 && (name.contains(keyword) || library.contains(keyword))) {
                        isRelevant = true;
                        break;
                    }
                }
                
                if (isRelevant) {
                    Map<String, String> importInfo = new HashMap<>();
                    importInfo.put("name", extLoc.getLabel());
                    importInfo.put("library", libraryName);
                    relevantImports.add(importInfo);
                }
            }
        }
        
        return relevantImports;
    }
    
    private List<Map<String, Object>> findRelevantFunctions(String question) {
        List<Map<String, Object>> relevantFunctions = new ArrayList<>();
        
        // Get question keywords
        Set<String> keywords = new HashSet<>();
        for (String word : question.toLowerCase().split("\\s+")) {
            if (word.length() > 3) {
                keywords.add(word);
            }
        }
        
        // Add specific domain keywords based on the question
        if (question.toLowerCase().contains("network")) {
            keywords.addAll(Arrays.asList("socket", "connect", "send", "recv", "http", "request"));
        }
        
        if (question.toLowerCase().contains("file")) {
            keywords.addAll(Arrays.asList("file", "open", "read", "write", "save", "load"));
        }
        
        if (question.toLowerCase().contains("crypto")) {
            keywords.addAll(Arrays.asList("encrypt", "decrypt", "aes", "rsa", "hash", "md5", "sha"));
        }
        
        if (question.toLowerCase().contains("ui") || question.toLowerCase().contains("interface")) {
            keywords.addAll(Arrays.asList("window", "dialog", "button", "display", "show"));
        }
        
        // Scan functions and check relevance
        FunctionManager functionManager = currentProgram.getFunctionManager();
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);
        
        int count = 0;
        int maxFunctions = 10; // Limit the number of functions to return
        
        Iterator<Function> funcIter = functionManager.getFunctions(true);
        while (funcIter.hasNext() && count < maxFunctions) {
            Function function = funcIter.next();
            
            // Skip very small functions (likely stubs)
            if (function.getBody().getNumAddresses() < 10) {
                continue;
            }
            
            // Skip external functions
            if (function.isExternal()) {
                continue;
            }
            
            // Check if name is relevant
            boolean nameIsRelevant = false;
            String functionName = function.getName().toLowerCase();
            
            for (String keyword : keywords) {
                if (functionName.contains(keyword)) {
                    nameIsRelevant = true;
                    break;
                }
            }
            
            // If name is relevant or function is large, check the decompiled code
            if (nameIsRelevant || function.getBody().getNumAddresses() > 100) {
                try {
                    DecompileResults results = decompInterface.decompileFunction(function, 0, TaskMonitor.DUMMY);
                    
                    if (results.decompileCompleted()) {
                        String code = results.getDecompiledFunction().getC();
                        
                        // Check if code contains keywords
                        boolean codeIsRelevant = nameIsRelevant; // If name matched, it's already relevant
                        
                        if (!codeIsRelevant) {
                            for (String keyword : keywords) {
                                if (code.toLowerCase().contains(keyword)) {
                                    codeIsRelevant = true;
                                    break;
                                }
                            }
                        }
                        
                        if (codeIsRelevant) {
                            Map<String, Object> functionInfo = getFunctionDetails(function);
                            functionInfo.put("decompiled", code);
                            relevantFunctions.add(functionInfo);
                            
                            count++;
                        }
                    }
                } catch (Exception e) {
                    // Skip functions that fail to decompile
                    continue;
                }
            }
        }
        
        return relevantFunctions;
    }
    
    private Map<String, Object> performSecurityAnalysis() {
        Map<String, Object> securityAnalysis = new HashMap<>();
        
        // Check for security-relevant imports
        List<String> securityImports = new ArrayList<>();
        ExternalManager externalManager = currentProgram.getExternalManager();
        
        // Define security-relevant function patterns
        String[] securityFunctions = {
            "strcpy", "strcat", "sprintf", "gets", // Buffer overflow
            "exec", "system", "popen", "ShellExecute", // Command injection
            "crypt", "encrypt", "decrypt", "password", // Crypto
            "memcpy", "memmove", "malloc", "free", // Memory management
            "rand", "random", "srand" // Random number generation
        };
        
        for (String libraryName : externalManager.getExternalLibraryNames()) {
            Iterator<ExternalLocation> extLocIter = externalManager.getExternalLocations(libraryName);
            while (extLocIter.hasNext()) {
                ExternalLocation extLoc = extLocIter.next();
                String name = extLoc.getLabel().toLowerCase();
                
                for (String secFunc : securityFunctions) {
                    if (name.contains(secFunc)) {
                        securityImports.add(extLoc.getLabel() + " from " + libraryName);
                        break;
                    }
                }
            }
        }
        securityAnalysis.put("security_imports", securityImports);
        
        // Check for potential vulnerabilities in code
        List<Map<String, Object>> potentialVulnerabilities = new ArrayList<>();
        
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> funcIter = functionManager.getFunctions(true);
        while (funcIter.hasNext()) {
            Function function = funcIter.next();
            if (function.isExternal()) continue;
            
            try {
                DecompInterface decompInterface = new DecompInterface();
                decompInterface.openProgram(currentProgram);
                DecompileResults results = decompInterface.decompileFunction(function, 0, TaskMonitor.DUMMY);
                
                if (results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC().toLowerCase();
                    
                    // Check for various vulnerability patterns
                    checkVulnerabilityPatterns(function, code, potentialVulnerabilities);
                }
            } catch (Exception e) {
                // Skip functions that fail to decompile
            }
        }
        securityAnalysis.put("potential_vulnerabilities", potentialVulnerabilities);
        
        return securityAnalysis;
    }
    
    private void checkVulnerabilityPatterns(Function function, String code, 
                                            List<Map<String, Object>> vulnerabilities) {
        // Check for common vulnerability patterns
        Map<String, String> patterns = new HashMap<>();
        patterns.put("buffer_overflow", "\\b(strcpy|strcat|sprintf|gets)\\s*\\(");
        patterns.put("command_injection", "\\b(system|exec|popen|shellexecute)\\s*\\(");
        patterns.put("format_string", "printf\\s*\\([^\"]*,[^\"]*\\)");
        patterns.put("integer_overflow", "\\b(malloc|alloca)\\s*\\([^)]*\\*[^)]*\\)");
        patterns.put("use_after_free", "free\\s*\\([^)]+\\)[^;]*\\1");
        
        for (Map.Entry<String, String> pattern : patterns.entrySet()) {
            if (code.matches(".*" + pattern.getValue() + ".*")) {
                Map<String, Object> vulnerability = new HashMap<>();
                vulnerability.put("function", function.getName());
                vulnerability.put("address", function.getEntryPoint().toString());
                vulnerability.put("type", pattern.getKey());
                vulnerability.put("description", "Potential " + pattern.getKey() + 
                                " vulnerability detected in function " + function.getName());
                vulnerabilities.add(vulnerability);
            }
        }
    }
    
    private List<Map<String, Object>> getMemorySections() {
        List<Map<String, Object>> sections = new ArrayList<>();
        
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            Map<String, Object> section = new HashMap<>();
            section.put("name", block.getName());
            section.put("start", block.getStart().toString());
            section.put("end", block.getEnd().toString());
            section.put("size", block.getSize());
            section.put("readable", block.isRead());
            section.put("writable", block.isWrite());
            section.put("executable", block.isExecute());
            section.put("initialized", block.isInitialized());
            sections.add(section);
        }
        
        return sections;
    }
}