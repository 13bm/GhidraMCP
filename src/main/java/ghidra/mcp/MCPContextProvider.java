package ghidra.mcp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

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