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
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.CommentType;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.util.Msg;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.Equate;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.LocalSymbolMap;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class MCPContextProvider {
    private volatile Program currentProgram;
    private PluginTool tool;

    /** Maximum number of concurrent async decompilation tasks to prevent unbounded growth. */
    private static final int MAX_ASYNC_TASKS = 100;

    /** Stores async decompilation tasks keyed by task ID. */
    private final ConcurrentHashMap<String, CompletableFuture<String>> asyncTasks = new ConcurrentHashMap<>();

    /** Scheduled executor for cleaning up completed async tasks after TTL expiry. */
    private static final ScheduledExecutorService cleanupScheduler =
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "MCP-AsyncCleanup");
            t.setDaemon(true);
            return t;
        });

    /** Dedicated thread pool for async decompilation (separate from MCPServer's connection pool). */
    private final ExecutorService decompilerPool = Executors.newFixedThreadPool(
        Math.max(2, Runtime.getRuntime().availableProcessors() / 2),
        r -> {
            Thread t = new Thread(r, "MCP-Decompiler");
            t.setDaemon(true);
            return t;
        }
    );

    public MCPContextProvider(PluginTool tool) {
        this.tool = tool;
    }

    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
    }

    /**
     * Resolves an address string to a Ghidra Address, or throws if invalid.
     * @param addressStr the address string (e.g. "0x00401000")
     * @return the resolved Address
     * @throws IllegalArgumentException if the address is null, empty, or invalid
     */
    private ghidra.program.model.address.Address resolveAddress(String addressStr) {
        if (addressStr == null || addressStr.trim().isEmpty()) {
            throw new IllegalArgumentException("Address cannot be null or empty");
        }
        Program p = currentProgram;
        if (p == null) {
            throw new IllegalArgumentException("No program loaded");
        }
        ghidra.program.model.address.Address addr = p.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        return addr;
    }

    /**
     * Returns the current program, throwing if none is loaded.
     * Captures a local reference for thread safety.
     */
    private Program requireProgram() {
        Program p = currentProgram;
        if (p == null) {
            throw new IllegalArgumentException("No program loaded");
        }
        return p;
    }

    /**
     * Decompile a function and return the C code string.
     * Properly disposes the DecompInterface to avoid resource leaks.
     *
     * @param function The function to decompile
     * @return The decompiled C code, or null if decompilation failed
     */
    /** Default decompiler timeout in seconds. Large/complex functions may need more time. */
    private static final int DECOMPILE_TIMEOUT_SECS = 120;

    private String decompileToC(Function function) {
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(currentProgram);
            DecompileResults results = decomp.decompileFunction(function, DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
            if (results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            }
            return null;
        } finally {
            decomp.dispose();
        }
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

            String result = decompileToC(function);
            if (result != null) {
                return result;
            } else {
                return "Error: Decompilation failed";
            }

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    public Map<String, Object> getMemoryMap(int offset, int limit) {
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

        result.putAll(paginate(sections, offset, limit));
        return result;
    }
    
    public Map<String, Object> getAllFunctions(int offset, int limit) {
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

        result.putAll(paginate(functions, offset, limit));
        return result;
    }

    /**
     * Get defined strings from the program with pagination and optional filtering.
     *
     * @param offset Number of strings to skip
     * @param limit Maximum number of strings to return
     * @param filter Optional case-insensitive substring filter on string content (null to skip)
     * @return Map containing strings list, count, and totalCount
     */
    public Map<String, Object> getStrings(int offset, int limit, String filter) {
        Map<String, Object> result = new HashMap<>();

        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }

        List<Map<String, Object>> allStrings = new ArrayList<>();
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);

        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            String typeName = data.getDataType().getName().toLowerCase();

            // Filter for string-like data types
            if (typeName.contains("string") || typeName.contains("unicode") ||
                (typeName.contains("char") && typeName.contains("["))) {

                String value = data.getDefaultValueRepresentation();
                if (value == null) {
                    value = "";
                }

                // Apply content filter if specified
                if (filter != null && !filter.isEmpty()) {
                    if (!value.toLowerCase().contains(filter.toLowerCase())) {
                        continue;
                    }
                }

                Map<String, Object> stringInfo = new HashMap<>();
                stringInfo.put("address", data.getAddress().toString());
                stringInfo.put("value", value);
                stringInfo.put("type", data.getDataType().getName());
                stringInfo.put("length", data.getLength());
                allStrings.add(stringInfo);
            }
        }

        // Paginate
        int total = allStrings.size();
        int start = Math.min(offset, total);
        int end = Math.min(start + limit, total);

        result.put("strings", allStrings.subList(start, end));
        result.put("count", end - start);
        result.put("totalCount", total);
        return result;
    }

    /**
     * Get imported symbols with pagination.
     *
     * @param offset Number of imports to skip
     * @param limit Maximum number of imports to return
     * @return Map containing imports list, count, and totalCount
     */
    public Map<String, Object> getImports(int offset, int limit) {
        Map<String, Object> result = new HashMap<>();

        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }

        List<Map<String, Object>> allImports = new ArrayList<>();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        ExternalManager extManager = currentProgram.getExternalManager();
        SymbolIterator extSymbols = symbolTable.getExternalSymbols();

        while (extSymbols.hasNext()) {
            Symbol symbol = extSymbols.next();
            Map<String, Object> importInfo = new HashMap<>();
            importInfo.put("name", symbol.getName());
            importInfo.put("address", symbol.getAddress().toString());

            // Try to get library name
            try {
                ExternalLocation extLoc = extManager.getExternalLocation(symbol);
                if (extLoc != null && extLoc.getLibraryName() != null) {
                    importInfo.put("library", extLoc.getLibraryName());
                }
            } catch (Exception e) {
                // Library name not available
            }

            allImports.add(importInfo);
        }

        // Paginate
        int total = allImports.size();
        int start = Math.min(offset, total);
        int end = Math.min(start + limit, total);

        result.put("imports", allImports.subList(start, end));
        result.put("count", end - start);
        result.put("totalCount", total);
        return result;
    }

    /**
     * Get exported symbols (entry points) with pagination.
     *
     * @param offset Number of exports to skip
     * @param limit Maximum number of exports to return
     * @return Map containing exports list, count, and totalCount
     */
    public Map<String, Object> getExports(int offset, int limit) {
        Map<String, Object> result = new HashMap<>();

        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }

        List<Map<String, Object>> allExports = new ArrayList<>();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);

        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            if (symbol.isExternalEntryPoint()) {
                Map<String, Object> exportInfo = new HashMap<>();
                exportInfo.put("name", symbol.getName());
                exportInfo.put("address", symbol.getAddress().toString());
                allExports.add(exportInfo);
            }
        }

        // Paginate
        int total = allExports.size();
        int start = Math.min(offset, total);
        int end = Math.min(start + limit, total);

        result.put("exports", allExports.subList(start, end));
        result.put("count", end - start);
        result.put("totalCount", total);
        return result;
    }

    /**
     * Rename a function using either its current name or address.
     *
     * @param identifier Either a function name or address
     * @param newName The new name to assign to the function
     * @param isAddress If true, identifier is treated as an address; otherwise as a name
     * @return Map containing success status and detailed information
     */
    public Map<String, Object> renameFunction(String identifier, String newName, boolean isAddress) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        try {
            // Run on the Swing thread for thread safety
            SwingUtilities.invokeAndWait(() -> {
                // Start a transaction for proper undo/redo support
                int txId = currentProgram.startTransaction("Rename Function");
                
                try {
                    // Find the function either by name or address
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Function targetFunction = null;
                    
                    if (isAddress) {
                        // Find by address
                        Address address = currentProgram.getAddressFactory().getAddress(identifier);
                        if (address == null) {
                            result.put("error", "Invalid address: " + identifier);
                            return;
                        }
                        
                        targetFunction = functionManager.getFunctionAt(address);
                        if (targetFunction == null) {
                            result.put("error", "No function found at address " + identifier);
                            return;
                        }
                    } else {
                        // Find by name
                        Iterator<Function> functions = functionManager.getFunctions(true);
                        while (functions.hasNext()) {
                            Function function = functions.next();
                            if (function.getName().equals(identifier)) {
                                targetFunction = function;
                                break;
                            }
                        }
                        
                        if (targetFunction == null) {
                            result.put("error", "No function found with name '" + identifier + "'");
                            return;
                        }
                    }
                    
                    // Validate the new name
                    if (newName == null || newName.trim().isEmpty()) {
                        result.put("error", "New function name cannot be empty");
                        return;
                    }
                    
                    // Check if the new name already exists
                    Iterator<Function> functions = functionManager.getFunctions(true);
                    while (functions.hasNext()) {
                        Function function = functions.next();
                        if (function.getName().equals(newName) && !function.equals(targetFunction)) {
                            result.put("error", "Function name '" + newName + "' already exists");
                            return;
                        }
                    }
                    
                    // Store old details for the result
                    String oldName = targetFunction.getName();
                    String address = targetFunction.getEntryPoint().toString();
                    
                    // Rename the function
                    try {
                        targetFunction.setName(newName, SourceType.USER_DEFINED);
                        
                        result.put("success", true);
                        result.put("oldName", oldName);
                        result.put("newName", newName);
                        result.put("address", address);
                        
                        Msg.info(this, "Renamed function from '" + oldName + "' to '" + newName + "' at " + address);
                    } catch (DuplicateNameException e) {
                        result.put("error", "Duplicate name: " + e.getMessage());
                    } catch (InvalidInputException e) {
                        result.put("error", "Invalid name: " + e.getMessage());
                    }
                } catch (Exception e) {
                    result.put("error", "Error renaming function: " + e.getMessage());
                    Msg.error(this, "Error renaming function: " + e.getMessage());
                    e.printStackTrace();
                } finally {
                    // End the transaction, applying changes if successful
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
            e.printStackTrace();
        }
        
        return result;
    }
    /**
     * Rename a data label at the specified address with enhanced error handling and options.
     * 
     * @param addressStr The address of the data to rename
     * @param newName The new name to assign to the data
     * @param options Optional parameters like namespace, force rename, etc. (can be null)
     * @return Map containing success status and detailed information
     */
    public Map<String, Object> renameData(String addressStr, String newName, Map<String, Object> options) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        if (options == null) {
            options = new HashMap<>(); // Default empty options
        }
        
        // Extract options with defaults
        boolean forceRename = options.containsKey("forceRename") ? (Boolean) options.get("forceRename") : false;
        boolean isPrimary = options.containsKey("isPrimary") ? (Boolean) options.get("isPrimary") : true;
        String namespaceName = (String) options.getOrDefault("namespace", null);
        
        try {
            // Run on the Swing thread for thread safety
            SwingUtilities.invokeAndWait(() -> {
                // Start a transaction for proper undo/redo support
                int txId = currentProgram.startTransaction("Rename Data");
                
                try {
                    // Convert the address string to an Address object
                    Address address = currentProgram.getAddressFactory().getAddress(addressStr);
                    if (address == null) {
                        result.put("error", "Invalid address: " + addressStr);
                        return;
                    }
                    
                    // Validate the new name
                    if (newName == null || newName.trim().isEmpty()) {
                        result.put("error", "New data name cannot be empty");
                        return;
                    }
                    
                    // Get the symbol table
                    SymbolTable symbolTable = currentProgram.getSymbolTable();
                    
                    // Determine which namespace to use
                    Namespace namespace = currentProgram.getGlobalNamespace();
                    if (namespaceName != null && !namespaceName.isEmpty()) {
                        Namespace foundNs = symbolTable.getNamespace(namespaceName, currentProgram.getGlobalNamespace());
                        if (foundNs != null) {
                            namespace = foundNs;
                        } else {
                            result.put("warning", "Namespace '" + namespaceName + "' not found. Using global namespace.");
                        }
                    }
                    
                    // Check if there's a defined data at this address
                    Data data = currentProgram.getListing().getDataAt(address);
                    if (data == null && !forceRename) {
                        result.put("error", "No defined data at address " + addressStr);
                        return;
                    }
                    
                    // Store data information for the result
                    if (data != null) {
                        result.put("dataType", data.getDataType().getName());
                        result.put("size", data.getLength());
                    }
                    
                    Symbol symbol = symbolTable.getPrimarySymbol(address);
                    String oldName = (symbol != null) ? symbol.getName() : null;
                    
                    try {
                        if (symbol != null) {
                            // Rename existing symbol
                            if (isPrimary && !symbol.isPrimary()) {
                                // Make it the primary symbol if requested
                                symbol.setPrimary();
                            }
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            result.put("oldName", oldName);
                            Msg.info(this, "Renamed data from '" + oldName + "' to '" + newName + "' at " + addressStr);
                        } else {
                            // Create a new symbol with the specified name
                            symbolTable.createLabel(address, newName, namespace, SourceType.USER_DEFINED);
                            result.put("oldName", null);
                            Msg.info(this, "Created new label '" + newName + "' at " + addressStr);
                        }
                        
                        result.put("success", true);
                        result.put("newName", newName);
                        result.put("address", addressStr);
                        result.put("namespace", namespace.getName());
                        
                    } catch (DuplicateNameException e) {
                        result.put("error", "Duplicate name: " + e.getMessage());
                    } catch (InvalidInputException e) {
                        result.put("error", "Invalid name: " + e.getMessage());
                    }
                    
                } catch (Exception e) {
                    result.put("error", "Error renaming data: " + e.getMessage());
                    Msg.error(this, "Error renaming data: " + e.getMessage());
                    e.printStackTrace();
                } finally {
                    // End the transaction, applying changes if successful
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
            e.printStackTrace();
        }
        
        return result;
    }

    /**
     * Rename a variable within a function.
     * 
     * @param functionAddress Address of the function containing the variable
     * @param oldName Current name of the variable
     * @param newName New name to assign to the variable
     * @return true if successful, false otherwise
     */
    public boolean renameVariable(String functionAddress, String oldName, String newName) {
        if (currentProgram == null) {
            return false;
        }

        final boolean[] success = new boolean[1];
        success[0] = false;

        try {
            // Run on the Swing thread for thread safety
            SwingUtilities.invokeAndWait(() -> {
                // Start a transaction for proper undo/redo support
                int txId = currentProgram.startTransaction("Rename Variable");

                try {
                    Address address = currentProgram.getAddressFactory().getAddress(functionAddress);
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Function function = functionManager.getFunctionAt(address);

                    if (function == null) {
                        Msg.error(this, "No function found at address " + functionAddress);
                        return;
                    }

                    // Check parameters first
                    Variable[] parameters = function.getParameters();
                    for (Variable param : parameters) {
                        if (param.getName().equals(oldName)) {
                            param.setName(newName, SourceType.USER_DEFINED);
                            success[0] = true;
                            return;
                        }
                    }

                    // Then check local variables
                    Variable[] locals = function.getLocalVariables();
                    for (Variable local : locals) {
                        if (local.getName().equals(oldName)) {
                            local.setName(newName, SourceType.USER_DEFINED);
                            success[0] = true;
                            return;
                        }
                    }

                    // Fallback: decompiler-generated names (uVar1, local_10, etc.)
                    // only exist in the HighFunction model, not the listing model.
                    DecompInterface decomp = new DecompInterface();
                    try {
                        decomp.openProgram(currentProgram);
                        DecompileResults decompResults = decomp.decompileFunction(
                                function, DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
                        if (decompResults.decompileCompleted()) {
                            HighFunction highFunc = decompResults.getHighFunction();
                            if (highFunc != null) {
                                LocalSymbolMap localSymbolMap = highFunc.getLocalSymbolMap();
                                Iterator<HighSymbol> symIter = localSymbolMap.getSymbols();
                                while (symIter.hasNext()) {
                                    HighSymbol sym = symIter.next();
                                    if (sym.getName().equals(oldName)) {
                                        HighFunctionDBUtil.updateDBVariable(sym,
                                                newName, null, SourceType.USER_DEFINED);
                                        success[0] = true;
                                        return;
                                    }
                                }
                            }
                        }
                    } finally {
                        decomp.dispose();
                    }

                    // If we get here, we didn't find the variable anywhere
                    Msg.error(this, "No variable named '" + oldName + "' found in function at " + functionAddress);

                } catch (Exception e) {
                    Msg.error(this, "Error renaming variable: " + e.getMessage());
                    e.printStackTrace();
                } finally {
                    // End the transaction, applying changes if successful
                    currentProgram.endTransaction(txId, success[0]);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
            e.printStackTrace();
        }

        return success[0];
    }

    /**
     * Get all variables in a function including parameters and local variables.
     * 
     * @param functionAddress Address of the function
     * @return Map containing details about all variables in the function
     */
    public Map<String, Object> getVariables(String functionAddress) {
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
            
            // Get parameter information
            List<Map<String, Object>> parameters = new ArrayList<>();
            Variable[] params = function.getParameters();
            for (Variable param : params) {
                Map<String, Object> paramInfo = new HashMap<>();
                paramInfo.put("name", param.getName());
                paramInfo.put("dataType", param.getDataType().getName());
                paramInfo.put("firstUseOffset", param.getFirstUseOffset());
                paramInfo.put("type", "parameter");
                paramInfo.put("storage", param.getVariableStorage().toString());
                paramInfo.put("source", param.getSource().toString());
                parameters.add(paramInfo);
            }
            result.put("parameters", parameters);
            
            // Get local variable information
            List<Map<String, Object>> localVars = new ArrayList<>();
            Variable[] locals = function.getLocalVariables();
            for (Variable local : locals) {
                Map<String, Object> localInfo = new HashMap<>();
                localInfo.put("name", local.getName());
                localInfo.put("dataType", local.getDataType().getName());
                localInfo.put("firstUseOffset", local.getFirstUseOffset());
                localInfo.put("type", "local");
                localInfo.put("storage", local.getVariableStorage().toString());
                localInfo.put("source", local.getSource().toString());
                
                // Get the stack frame offset for stack variables
                if (local.isStackVariable()) {
                    localInfo.put("stackOffset", local.getStackOffset());
                }
                
                // Get register name for register variables
                if (local.isRegisterVariable()) {
                    localInfo.put("register", local.getRegister().getName());
                }
                
                localVars.add(localInfo);
            }
            result.put("localVariables", localVars);
            
            // Get function signature
            result.put("signature", function.getSignature().toString());
            result.put("returnType", function.getReturnType().getName());
            
            return result;
        } catch (Exception e) {
            result.put("error", e.getMessage());
            return result;
        }
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
            
            // Collect the API calls and categorize them
            List<Map<String, Object>> apiCalls = new ArrayList<>();
            Set<Function> calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            
            for (Function calledFunc : calledFunctions) {
                if (calledFunc.isExternal()) {
                    Map<String, Object> apiInfo = new HashMap<>();
                    apiInfo.put("name", calledFunc.getName());
                    String library = calledFunc.getExternalLocation().getLibraryName();
                    apiInfo.put("library", library);
                    
                    // Categorize the API by functionality
                    String category = categorizeAPI(calledFunc.getName(), library);
                    apiInfo.put("category", category);
                    
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
                    
                    // Assess security risk if applicable
                    String riskLevel = assessSecurityRisk(calledFunc.getName(), library);
                    if (riskLevel != null) {
                        apiInfo.put("securityRisk", riskLevel);
                        
                        // For high-risk functions, add security notes
                        if ("high".equals(riskLevel)) {
                            apiInfo.put("securityNotes", getSecurityNotes(calledFunc.getName()));
                        }
                    }
                    
                    apiCalls.add(apiInfo);
                }
            }
            
            result.put("function", function.getName());
            result.put("apiCalls", apiCalls);
            
            // Get API call sequence as a timeline (in order of appearance)
            List<Map<String, Object>> callSequence = getApiCallTimeline(function);
            result.put("callSequence", callSequence);
            
            // Add decompiled code for Claude to analyze patterns
            String decompiled = getDecompiledCode(functionAddress);
            result.put("decompiled", decompiled);
            
            // Add summary of API functionality
            Map<String, Integer> categoryCounts = new HashMap<>();
            for (Map<String, Object> apiCall : apiCalls) {
                String category = (String) apiCall.get("category");
                categoryCounts.put(category, categoryCounts.getOrDefault(category, 0) + 1);
            }
            result.put("categorySummary", categoryCounts);
            
            // Overall security assessment
            int highRiskCount = 0;
            int mediumRiskCount = 0;
            for (Map<String, Object> apiCall : apiCalls) {
                String risk = (String) apiCall.get("securityRisk");
                if ("high".equals(risk)) {
                    highRiskCount++;
                } else if ("medium".equals(risk)) {
                    mediumRiskCount++;
                }
            }
            
            Map<String, Object> securitySummary = new HashMap<>();
            securitySummary.put("highRiskCount", highRiskCount);
            securitySummary.put("mediumRiskCount", mediumRiskCount);
            
            if (highRiskCount > 0) {
                securitySummary.put("overallRisk", "high");
            } else if (mediumRiskCount > 0) {
                securitySummary.put("overallRisk", "medium");
            } else {
                securitySummary.put("overallRisk", "low");
            }
            
            result.put("securitySummary", securitySummary);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    private String categorizeAPI(String functionName, String library) {
        String name = functionName.toLowerCase();
        String lib = library.toLowerCase();
        
        // Memory functions
        if (name.contains("alloc") || name.contains("free") || name.contains("mem") || 
            name.contains("heap") || name.contains("buffer")) {
            return "memory";
        }
        
        // File operations
        if (name.contains("file") || name.contains("open") || name.contains("close") || 
            name.contains("read") || name.contains("write") || name.contains("delete") ||
            name.contains("create")) {
            return "file";
        }
        
        // Network operations
        if (name.contains("socket") || name.contains("connect") || name.contains("bind") || 
            name.contains("listen") || name.contains("accept") || name.contains("recv") || 
            name.contains("send") || name.contains("http") || name.contains("url") ||
            lib.contains("ws2") || lib.contains("socket") || lib.contains("net")) {
            return "network";
        }
        
        // Cryptography
        if (name.contains("crypt") || name.contains("aes") || name.contains("des") || 
            name.contains("rsa") || name.contains("sha") || name.contains("md5") || 
            name.contains("hash") || name.contains("ssl") || name.contains("tls") ||
            lib.contains("crypt") || lib.contains("ssl")) {
            return "crypto";
        }
        
        // Process/Thread operations
        if (name.contains("process") || name.contains("thread") || name.contains("create") || 
            name.contains("terminate") || name.contains("exit") || name.contains("wait") ||
            name.contains("mutex") || name.contains("semaphore") || name.contains("critical")) {
            return "process";
        }
        
        // Registry operations
        if (name.contains("reg") && (name.contains("open") || name.contains("get") || 
            name.contains("set") || name.contains("query") || name.contains("create") ||
            name.contains("delete"))) {
            return "registry";
        }
        
        // String operations
        if (name.contains("str") && (name.contains("cat") || name.contains("cpy") || 
            name.contains("len") || name.contains("cmp") || name.contains("fmt"))) {
            return "string";
        }
        
        // UI/Graphics operations
        if (name.contains("window") || name.contains("dialog") || name.contains("gui") || 
            name.contains("draw") || name.contains("paint") || name.contains("message") ||
            lib.contains("user32") || lib.contains("gdi")) {
            return "ui";
        }
        
        // System information
        if (name.contains("get") && (name.contains("system") || name.contains("computer") || 
            name.contains("os") || name.contains("version") || name.contains("info"))) {
            return "system";
        }
        
        // Default category
        return "other";
    }
    
    private String assessSecurityRisk(String functionName, String library) {
        String name = functionName.toLowerCase();
        
        // High-risk functions
        String[] highRiskFunctions = {
            "strcpy", "strcat", "sprintf", "gets", "scanf", // Buffer overflow
            "system", "exec", "popen", "shellexecute", // Command injection
            "createprocess", "winexec", // Process execution
            "loadlibrary", "getprocaddress", // Dynamic loading
            "virtualalloc", "virtualprotect", // Memory manipulation
            "wcscpy", "wcscat", "memcpy", "memmove", // Memory operations without bounds checking
            "realloc", "free" // Memory corruption
        };
        
        // Medium-risk functions
        String[] mediumRiskFunctions = {
            "rand", "srand", // Weak randomness
            "printf", "fprintf", // Format string
            "open", "fopen", "createfile", // File operations
            "socket", "bind", "connect", "listen", // Network operations
            "regopen", "regset", "regget", // Registry operations
            "malloc", "calloc", // Memory allocation
            "getenv", "getenvvar" // Environment variables
        };
        
        // Check for high-risk functions
        for (String func : highRiskFunctions) {
            if (name.equals(func) || name.endsWith(func)) {
                return "high";
            }
        }
        
        // Check for medium-risk functions
        for (String func : mediumRiskFunctions) {
            if (name.equals(func) || name.endsWith(func)) {
                return "medium";
            }
        }
        
        // Functions taking user input are medium risk
        if (name.contains("input") || name.contains("read") || name.contains("get") || 
            name.contains("recv") || name.contains("accept")) {
            return "medium";
        }
        
        return "low";
    }
    
    private String getSecurityNotes(String functionName) {
        String name = functionName.toLowerCase();
        
        // Buffer overflow vulnerabilities
        if (name.equals("strcpy") || name.equals("strcat") || name.equals("sprintf") || 
            name.equals("gets") || name.equals("wcscpy") || name.equals("wcscat")) {
            return "This function does not perform bounds checking and can lead to buffer overflows. " +
                   "Consider using a safer alternative with bounds checking.";
        }
        
        // Command injection vulnerabilities
        if (name.equals("system") || name.equals("exec") || name.equals("popen") || 
            name.equals("shellexecute") || name.equals("winexec")) {
            return "This function executes commands on the system. If user input is passed to this function, " +
                   "it may allow command injection attacks.";
        }
        
        // Memory corruption
        if (name.equals("free") || name.equals("realloc")) {
            return "Improper use of this function can lead to use-after-free or double-free vulnerabilities.";
        }
        
        // Format string vulnerabilities
        if (name.equals("printf") || name.equals("fprintf") || name.equals("sprintf")) {
            return "If user input is used as a format string, this function can lead to format string vulnerabilities.";
        }
        
        // Default note for other high-risk functions
        return "This function is considered high-risk from a security perspective.";
    }
    
    private List<Map<String, Object>> getApiCallTimeline(Function function) {
        List<Map<String, Object>> timeline = new ArrayList<>();
        
        try {
            // Get all references from the function using ReferenceManager
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            List<Reference> references = new ArrayList<>();
            AddressIterator addrIter = refMgr.getReferenceSourceIterator(function.getBody(), true);
            while (addrIter.hasNext()) {
                Address fromAddr = addrIter.next();
                for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                    references.add(ref);
                }
            }

            // Sort by address
            references.sort((r1, r2) -> r1.getFromAddress().compareTo(r2.getFromAddress()));

            for (Reference ref : references) {
                // Check if the reference is a call
                if (ref.getReferenceType().isCall()) {
                    // Get the target function
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Function targetFunc = functionManager.getFunctionAt(ref.getToAddress());

                    if (targetFunc != null && targetFunc.isExternal()) {
                        Map<String, Object> callInfo = new HashMap<>();
                        callInfo.put("address", ref.getFromAddress().toString());
                        callInfo.put("function", targetFunc.getName());
                        callInfo.put("library", targetFunc.getExternalLocation().getLibraryName());
                        callInfo.put("category", categorizeAPI(targetFunc.getName(),
                                              targetFunc.getExternalLocation().getLibraryName()));
                        timeline.add(callInfo);
                    }
                }
            }
        } catch (Exception e) {
            // Handle exception
            Msg.error(this, "Error generating API call timeline: " + e.getMessage());
        }
        
        return timeline;
    }

    public Map<String, Object> identifyUserInputSources() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        // Provide a list of common input-related functions and their references
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
            
            // Generate hierarchical call graph
            Set<String> visited = new HashSet<>();
            Map<String, Object> callGraph = buildCallGraphNode(startFunction, maxDepth, visited);
            
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
            node.put("name", function.getName());
            node.put("address", function.getEntryPoint().toString());
            node.put("isExternal", function.isExternal());
            node.put("isRecursive", true);
            return node;
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
                    Map<String, Object> calleeNode = buildCallGraphNode(calledFunc, depth - 1, new HashSet<>(visited));
                    callees.add(calleeNode);
                }
                
                node.put("calls", callees);
                
                // Add basic complexity metrics
                node.put("complexity", estimateFunctionComplexity(function));
                
            } catch (Exception e) {
                // Handle any exception
                node.put("error", "Error retrieving called functions: " + e.getMessage());
            }
        }
        
        return node;
    }
    
    private Map<String, Object> estimateFunctionComplexity(Function function) {
        Map<String, Object> complexity = new HashMap<>();
        
        try {
            // Basic size metric
            complexity.put("instructionCount", function.getBody().getNumAddresses());
            
            // Control flow complexity
            int branchCount = 0;
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            AddressIterator addrIter = refMgr.getReferenceSourceIterator(function.getBody(), true);
            while (addrIter.hasNext()) {
                Address fromAddr = addrIter.next();
                for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                    if (ref.getReferenceType().isJump() || ref.getReferenceType().isConditional()) {
                        branchCount++;
                    }
                }
            }
            complexity.put("branchCount", branchCount);
            
            // Call complexity
            Set<Function> calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            complexity.put("callCount", calledFunctions.size());
            complexity.put("externalCallCount", 
                          calledFunctions.stream().filter(Function::isExternal).count());
            
            // Variables complexity
            complexity.put("parameterCount", function.getParameterCount());
            complexity.put("localVariableCount", function.getLocalVariables().length);
            
            // McCabe Cyclomatic Complexity (E - N + 2)
            // Where E = edges, N = nodes
            // Here we use a simple approximation: branchCount + 1
            complexity.put("cyclomaticComplexity", branchCount + 1);
            
        } catch (Exception e) {
            complexity.put("error", "Error estimating complexity: " + e.getMessage());
        }
        
        return complexity;
    }

    public Map<String, Object> identifyCryptographicPatterns() {
        Map<String, Object> result = new HashMap<>();
        
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        
        try {
            List<Map<String, Object>> cryptoImplementations = new ArrayList<>();
            
            // Find crypto-related functions based on name
            findCryptoFunctionsByName(cryptoImplementations);
            
            // Find crypto APIs
            findCryptoAPIUsage(cryptoImplementations);
            
            // Find crypto constants
            findCryptoConstants(cryptoImplementations);
            
            // Find functions with crypto characteristics
            findFunctionsWithCryptoCharacteristics(cryptoImplementations);
            
            result.put("cryptoImplementations", cryptoImplementations);
            result.put("count", cryptoImplementations.size());
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    private void findCryptoFunctionsByName(List<Map<String, Object>> cryptoImplementations) {
        String[] cryptoPatterns = {
            "crypt", "aes", "des", "rsa", "sha", "md5", "hash", "cipher", "decrypt", "encrypt"
        };
        
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> functions = functionManager.getFunctions(true);
        
        while (functions.hasNext()) {
            Function function = functions.next();
            String name = function.getName().toLowerCase();
            
            boolean isCryptoRelated = false;
            String matchedPattern = null;
            
            for (String pattern : cryptoPatterns) {
                if (name.contains(pattern)) {
                    isCryptoRelated = true;
                    matchedPattern = pattern;
                    break;
                }
            }
            
            if (isCryptoRelated) {
                Map<String, Object> cryptoImpl = new HashMap<>();
                cryptoImpl.put("name", function.getName());
                cryptoImpl.put("address", function.getEntryPoint().toString());
                cryptoImpl.put("type", "function");
                cryptoImpl.put("detectionMethod", "name");
                cryptoImpl.put("matchedPattern", matchedPattern);
                cryptoImpl.put("confidence", "medium");
                
                if (!function.isExternal()) {
                    String decompiled = getDecompiledCode(function.getEntryPoint().toString());
                    cryptoImpl.put("decompiled", decompiled);
                }
                
                cryptoImplementations.add(cryptoImpl);
            }
        }
    }
    
    private void findCryptoAPIUsage(List<Map<String, Object>> cryptoImplementations) {
        String[] cryptoAPIs = {
            "AES_", "EVP_", "SHA", "MD5", "Crypt", "BCrypt", "NCrypt", 
            "HMAC", "RSA_", "EC_", "BN_", "RAND_"
        };
        
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        
        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            String symbolName = symbol.getName();
            
            boolean isCryptoAPI = false;
            String matchedPattern = null;
            
            for (String apiPrefix : cryptoAPIs) {
                if (symbolName.startsWith(apiPrefix)) {
                    isCryptoAPI = true;
                    matchedPattern = apiPrefix;
                    break;
                }
            }
            
            if (isCryptoAPI) {
                Map<String, Object> cryptoImpl = new HashMap<>();
                cryptoImpl.put("name", symbolName);
                cryptoImpl.put("address", symbol.getAddress().toString());
                cryptoImpl.put("type", "API");
                cryptoImpl.put("detectionMethod", "name");
                cryptoImpl.put("matchedPattern", matchedPattern);
                cryptoImpl.put("confidence", "high");
                
                // Determine likely algorithm
                String name = symbolName.toLowerCase();
                if (name.contains("aes")) {
                    cryptoImpl.put("algorithm", "AES");
                } else if (name.contains("sha")) {
                    cryptoImpl.put("algorithm", "SHA");
                } else if (name.contains("rsa")) {
                    cryptoImpl.put("algorithm", "RSA");
                } else if (name.contains("md5")) {
                    cryptoImpl.put("algorithm", "MD5");
                } else {
                    cryptoImpl.put("algorithm", "Unknown");
                }
                
                // Find functions calling this API
                ReferenceManager refManager = currentProgram.getReferenceManager();
                List<String> callingFunctions = new ArrayList<>();
                
                Iterator<Reference> refs = refManager.getReferencesTo(symbol.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Function function = functionManager.getFunctionContaining(ref.getFromAddress());
                    
                    if (function != null) {
                        callingFunctions.add(function.getName() + "@" + function.getEntryPoint());
                    }
                }
                
                cryptoImpl.put("callingFunctions", callingFunctions);
                cryptoImplementations.add(cryptoImpl);
            }
        }
    }
    
    private void findCryptoConstants(List<Map<String, Object>> cryptoImplementations) {
        // Search for common crypto constants in data sections
        
        // AES S-box first few bytes
        byte[] aesSBoxPrefix = {(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b};
        
        // SHA-256 initial hash values in big-endian representation
        byte[] sha256Constants = {
            (byte)0x6a, (byte)0x09, (byte)0xe6, (byte)0x67,
            (byte)0xbb, (byte)0x67, (byte)0xae, (byte)0x85
        };
        
        // RC4 characteristic pattern
        byte[] rc4Pattern = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        
        Memory memory = currentProgram.getMemory();
        
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && !block.isExecute()) {
                try {
                    if (block.getSize() > 16) {
                        // Search for AES S-box
                        searchForPattern(block, aesSBoxPrefix, "AES S-box", "high", "AES", cryptoImplementations);
                        
                        // Search for SHA-256 constants
                        searchForPattern(block, sha256Constants, "SHA-256 Constants", "high", "SHA-256", cryptoImplementations);
                        
                        // Search for RC4 characteristic pattern (initial S-box setup)
                        searchForPattern(block, rc4Pattern, "Possible RC4 S-box initialization", "medium", "RC4", cryptoImplementations);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error searching for crypto constants: " + e.getMessage());
                }
            }
        }
    }
    
    private void searchForPattern(MemoryBlock block, byte[] pattern, String description, String confidence, String algorithm, 
                               List<Map<String, Object>> cryptoImplementations) throws Exception {
        byte[] buffer = new byte[Math.min(4096, (int)block.getSize())];
        
        // Search in 4K chunks
        for (long offset = 0; offset < block.getSize() - pattern.length; offset += buffer.length - pattern.length) {
            int readSize = Math.min(buffer.length, (int)(block.getSize() - offset));
            block.getBytes(block.getStart().add(offset), buffer, 0, readSize);
            
            // Search for pattern in the buffer
            for (int i = 0; i <= readSize - pattern.length; i++) {
                boolean match = true;
                for (int j = 0; j < pattern.length; j++) {
                    if (buffer[i + j] != pattern[j]) {
                        match = false;
                        break;
                    }
                }
                
                if (match) {
                    Map<String, Object> cryptoImpl = new HashMap<>();
                    Address patternAddr = block.getStart().add(offset + i);
                    cryptoImpl.put("address", patternAddr.toString());
                    cryptoImpl.put("type", "Constant");
                    cryptoImpl.put("detectionMethod", "pattern");
                    cryptoImpl.put("description", description);
                    cryptoImpl.put("algorithm", algorithm);
                    cryptoImpl.put("confidence", confidence);
                    
                    // Find references to this address
                    ReferenceManager refManager = currentProgram.getReferenceManager();
                    List<String> referencingFunctions = new ArrayList<>();
                    
                    Iterator<Reference> refs = refManager.getReferencesTo(patternAddr);
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        FunctionManager functionManager = currentProgram.getFunctionManager();
                        Function function = functionManager.getFunctionContaining(ref.getFromAddress());
                        
                        if (function != null) {
                            referencingFunctions.add(function.getName() + "@" + function.getEntryPoint());
                        }
                    }
                    
                    cryptoImpl.put("referencingFunctions", referencingFunctions);
                    cryptoImplementations.add(cryptoImpl);
                }
            }
        }
    }
    
    private void findFunctionsWithCryptoCharacteristics(List<Map<String, Object>> cryptoImplementations) {
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
                List<String> cryptoCharacteristics = new ArrayList<>();
                
                // Check for bit manipulation operations in decompiled code
                if (hasBitManipulationInstructions(function)) {
                    cryptoCharacteristics.add("Extensive bit manipulation operations");
                }
                
                // Check for lookup tables
                if (hasLookupTablePatterns(function)) {
                    cryptoCharacteristics.add("Lookup table access patterns");
                }
                
                // Check for round structures in loops
                if (hasRoundStructure(function)) {
                    cryptoCharacteristics.add("Multiple rounds/iterations structure");
                }
                
                // Check for permutation operations
                if (hasPermutationOperations(function)) {
                    cryptoCharacteristics.add("Permutation operations");
                }
                
                // If we found crypto characteristics, add the function
                if (!cryptoCharacteristics.isEmpty()) {
                    Map<String, Object> cryptoImpl = new HashMap<>();
                    cryptoImpl.put("name", function.getName());
                    cryptoImpl.put("address", function.getEntryPoint().toString());
                    cryptoImpl.put("type", "Function");
                    cryptoImpl.put("detectionMethod", "characteristics");
                    cryptoImpl.put("characteristics", cryptoCharacteristics);
                    cryptoImpl.put("confidence", cryptoCharacteristics.size() > 1 ? "medium" : "low");
                    cryptoImpl.put("algorithm", "Unknown");
                    
                    // Add decompiled code for further analysis
                    String decompiled = getDecompiledCode(function.getEntryPoint().toString());
                    cryptoImpl.put("decompiled", decompiled);
                    
                    cryptoImplementations.add(cryptoImpl);
                }
                
            } catch (Exception e) {
                // Skip this function if error
                Msg.error(this, "Error analyzing function for crypto characteristics: " + e.getMessage());
            }
        }
    }
    
    private boolean hasBitManipulationInstructions(Function function) {
        try {
            String code = decompileToC(function);
            if (code != null) {
                code = code.toLowerCase();
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

    private boolean hasLookupTablePatterns(Function function) {
        try {
            String code = decompileToC(function);
            if (code != null) {
                // Look for array access patterns like: sbox[byte & 0xff]
                return code.contains("[") && code.contains("&") &&
                    (code.contains("0xff") || code.contains("0xf") || code.contains("255"));
            }
        } catch (Exception e) {
            // Ignore
        }

        return false;
    }

    private boolean hasRoundStructure(Function function) {
        try {
            String code = decompileToC(function);
            if (code != null) {
                code = code.toLowerCase();

                // Check for multiple rounds/iterations - common in block ciphers
                if ((code.contains("round") || code.contains("iteration")) &&
                    (code.contains("for (") || code.contains("while ("))) {
                    return true;
                }

                // A large number of iterations is typical for crypto
                if ((code.contains("for (") || code.contains("while (")) &&
                    (code.contains(" < 16") || code.contains(" < 32") ||
                     code.contains(" < 64") || code.contains(" < 8"))) {
                    return true;
                }

                // Check for magic numbers often used in crypto
                if (code.contains("0x67452301") || // MD5
                    code.contains("0xc3d2e1f0") || // SHA-1
                    code.contains("0x5a827999") || // SHA-1 constant
                    code.contains("0x6a09e667")) { // SHA-256
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        }

        return false;
    }

    private boolean hasPermutationOperations(Function function) {
        try {
            String code = decompileToC(function);
            if (code != null) {
                code = code.toLowerCase();

                // Look for swapping operations (common in permutation-based crypto)
                return (code.contains("temp") || code.contains("swap") || code.contains("t =")) &&
                       code.contains("[") && code.contains("]") &&
                       code.contains("=") && code.contains(";");
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
            List<Map<String, Object>> potentialObfuscatedStrings = new ArrayList<>();
            
            // Find XOR-encoded strings
            findXorEncodedStrings(potentialObfuscatedStrings);
            
            // Find character-by-character string construction
            findConstructedStrings(potentialObfuscatedStrings);
            
            // Find stack strings (strings built on the stack)
            findStackStrings(potentialObfuscatedStrings);
            
            // Find functions that decrypt strings at runtime
            findStringDecryptionFunctions(potentialObfuscatedStrings);
            
            result.put("obfuscatedStrings", potentialObfuscatedStrings);
            result.put("count", potentialObfuscatedStrings.size());
            
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
                String code = decompileToC(function);
                if (code != null) {
                    String codeLower = code.toLowerCase();

                    // Look for XOR operations with potential keys
                    if (codeLower.contains(" ^ ") &&
                        (codeLower.contains("char") || codeLower.contains("byte"))) {

                        Map<String, Object> obfuscatedString = new HashMap<>();
                        obfuscatedString.put("type", "XOR-encoded");
                        obfuscatedString.put("function", function.getName());
                        obfuscatedString.put("address", function.getEntryPoint().toString());
                        obfuscatedString.put("detectionMethod", "XOR operation in code");

                        // Try to determine XOR key if possible
                        String key = extractPotentialXorKey(codeLower);
                        if (key != null) {
                            obfuscatedString.put("potentialKey", key);
                        }

                        // Add decompiled code for manual analysis
                        obfuscatedString.put("decompiled", codeLower);

                        obfuscatedStrings.add(obfuscatedString);
                    }
                }
            } catch (Exception e) {
                // Skip this function if error
                Msg.error(this, "Error analyzing function for XOR encoding: " + e.getMessage());
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
                String code = decompileToC(function);
                if (code != null) {
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
                        obfuscatedString.put("detectionMethod", "String building pattern");
                        obfuscatedString.put("decompiled", code);
                        obfuscatedStrings.add(obfuscatedString);
                    }
                }
            } catch (Exception e) {
                // Skip this function if error
                Msg.error(this, "Error analyzing function for string construction: " + e.getMessage());
            }
        }
    }
    
    private void findStackStrings(List<Map<String, Object>> obfuscatedStrings) {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> functions = functionManager.getFunctions(true);
        
        while (functions.hasNext()) {
            Function function = functions.next();
            
            // Skip external functions
            if (function.isExternal()) {
                continue;
            }
            
            try {
                // Check for byte array initializations on the stack
                Variable[] localVars = function.getLocalVariables();
                for (Variable var : localVars) {
                    // Look for char[] or byte[] arrays
                    if (var.getDataType().toString().contains("[") && 
                        (var.getDataType().toString().contains("char") || 
                         var.getDataType().toString().contains("byte"))) {
                        
                        // Check if this is a stack variable
                        if (var.isStackVariable()) {
                            // Get the decompiled code to look for initialization patterns
                            String code = decompileToC(function);
                            if (code != null) {
                                String varName = var.getName();

                                // Check if there are multiple initializations of this array
                                int initCount = 0;
                                int index = 0;
                                while ((index = code.indexOf(varName + "[", index)) != -1) {
                                    if (code.indexOf("=", index) != -1) {
                                        initCount++;
                                    }
                                    index += varName.length() + 1;
                                }

                                // If there are multiple initializations, it might be a stack string
                                if (initCount > 3) {
                                    Map<String, Object> obfuscatedString = new HashMap<>();
                                    obfuscatedString.put("type", "Stack string");
                                    obfuscatedString.put("function", function.getName());
                                    obfuscatedString.put("address", function.getEntryPoint().toString());
                                    obfuscatedString.put("variable", varName);
                                    obfuscatedString.put("detectionMethod", "Multiple array initializations");
                                    obfuscatedString.put("decompiled", code);
                                    obfuscatedStrings.add(obfuscatedString);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Skip this function if error
                Msg.error(this, "Error analyzing function for stack strings: " + e.getMessage());
            }
        }
    }
    
    private void findStringDecryptionFunctions(List<Map<String, Object>> obfuscatedStrings) {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> functions = functionManager.getFunctions(true);
        
        while (functions.hasNext()) {
            Function function = functions.next();
            
            // Skip external functions
            if (function.isExternal()) {
                continue;
            }
            
            try {
                // Check the pattern of parameters and return value
                if (function.getReturnType().getName().equals("char *") ||
                    function.getReturnType().getName().contains("*char") ||
                    function.getReturnType().getName().equals("String")) {

                    String code = decompileToC(function);
                    if (code != null) {
                        String codeLower = code.toLowerCase();

                        // Look for suspicious string manipulation operations
                        if ((codeLower.contains("char") || codeLower.contains("byte")) &&
                            (codeLower.contains(" ^ ") || codeLower.contains("+") || codeLower.contains("-")) &&
                            (codeLower.contains("for (") || codeLower.contains("while (")) &&
                            (codeLower.contains("return"))) {

                            Map<String, Object> obfuscatedString = new HashMap<>();
                            obfuscatedString.put("type", "String decryption function");
                            obfuscatedString.put("function", function.getName());
                            obfuscatedString.put("address", function.getEntryPoint().toString());
                            obfuscatedString.put("detectionMethod", "Function characteristics");

                            // Try to identify the algorithm used
                            String algorithm = "Unknown";
                            if (codeLower.contains(" ^ ")) {
                                algorithm = "XOR encryption";
                            } else if (codeLower.contains("+") || codeLower.contains("-")) {
                                algorithm = "Caesar cipher or ROT";
                            }
                            obfuscatedString.put("algorithm", algorithm);

                            // Find callers of this function
                            ReferenceManager refManager = currentProgram.getReferenceManager();
                            List<String> callers = new ArrayList<>();

                            Iterator<Reference> refs = refManager.getReferencesTo(function.getEntryPoint());
                            while (refs.hasNext()) {
                                Reference ref = refs.next();
                                Function callerFunc = functionManager.getFunctionContaining(ref.getFromAddress());

                                if (callerFunc != null) {
                                    callers.add(callerFunc.getName() + "@" + callerFunc.getEntryPoint());
                                }
                            }
                            obfuscatedString.put("callers", callers);

                            // Include decompiled code for manual analysis
                            obfuscatedString.put("decompiled", code);

                            obfuscatedStrings.add(obfuscatedString);
                        }
                    }
                }
            } catch (Exception e) {
                // Skip this function if error
                Msg.error(this, "Error analyzing function for string decryption: " + e.getMessage());
            }
        }
    }

    // ==================== PHASE 2 METHODS ====================

    // --- 2.1 Pagination utility ---

    private <T> Map<String, Object> paginate(List<T> items, int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        int total = items.size();
        int start = Math.min(offset, total);
        int end = Math.min(start + limit, total);
        result.put("items", items.subList(start, end));
        result.put("offset", start);
        result.put("limit", limit);
        result.put("totalCount", total);
        return result;
    }

    // --- 2.2 Query Methods ---

    public Map<String, Object> listClasses(int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            Set<String> seen = new HashSet<>();
            List<Map<String, Object>> classes = new ArrayList<>();
            SymbolIterator symbols = symbolTable.getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                Namespace ns = symbol.getParentNamespace();
                while (ns != null && !ns.isGlobal()) {
                    if (ns.getSymbol().getSymbolType().toString().equals("Class")) {
                        String key = ns.getName() + "@" + ns.getBody().getMinAddress();
                        if (!seen.contains(key)) {
                            seen.add(key);
                            Map<String, Object> classInfo = new HashMap<>();
                            classInfo.put("name", ns.getName());
                            classInfo.put("address", ns.getBody().getMinAddress().toString());
                            classes.add(classInfo);
                        }
                    }
                    ns = ns.getParentNamespace();
                }
            }
            result.putAll(paginate(classes, offset, limit));
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error listing classes: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> listNamespaces(int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            Set<String> seen = new HashSet<>();
            List<Map<String, Object>> namespaces = new ArrayList<>();
            SymbolIterator symbols = symbolTable.getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    String nsName = ns.getName(true);
                    if (!seen.contains(nsName)) {
                        seen.add(nsName);
                        Map<String, Object> nsInfo = new HashMap<>();
                        nsInfo.put("name", nsName);
                        nsInfo.put("type", ns.getSymbol().getSymbolType().toString());
                        namespaces.add(nsInfo);
                    }
                }
            }
            result.putAll(paginate(namespaces, offset, limit));
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error listing namespaces: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> listDataItems(int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            List<Map<String, Object>> dataItems = new ArrayList<>();
            DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                Map<String, Object> item = new HashMap<>();
                item.put("address", data.getAddress().toString());
                Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(data.getAddress());
                item.put("name", sym != null ? sym.getName() : null);
                item.put("type", data.getDataType().getName());
                item.put("length", data.getLength());
                item.put("value", data.getDefaultValueRepresentation());
                dataItems.add(item);
            }
            result.putAll(paginate(dataItems, offset, limit));
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error listing data items: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> searchFunctionsByName(String query, int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            String lowerQuery = query.toLowerCase();
            List<Map<String, Object>> exactMatches = new ArrayList<>();
            List<Map<String, Object>> partialMatches = new ArrayList<>();
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Iterator<Function> funcIter = functionManager.getFunctions(true);
            while (funcIter.hasNext()) {
                Function function = funcIter.next();
                String funcName = function.getName();
                String lowerName = funcName.toLowerCase();
                if (lowerName.contains(lowerQuery)) {
                    Map<String, Object> info = new HashMap<>();
                    info.put("name", funcName);
                    info.put("address", function.getEntryPoint().toString());
                    info.put("size", function.getBody().getNumAddresses());
                    if (lowerName.equals(lowerQuery)) {
                        exactMatches.add(info);
                    } else {
                        partialMatches.add(info);
                    }
                }
            }
            // Exact matches first, then partial matches
            List<Map<String, Object>> allMatches = new ArrayList<>(exactMatches.size() + partialMatches.size());
            allMatches.addAll(exactMatches);
            allMatches.addAll(partialMatches);
            result.putAll(paginate(allMatches, offset, limit));
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error searching functions: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> decompileFunctionByName(String name) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Iterator<Function> funcIter = functionManager.getFunctions(true);
            Function target = null;
            while (funcIter.hasNext()) {
                Function f = funcIter.next();
                if (f.getName().equals(name)) {
                    target = f;
                    break;
                }
            }
            if (target == null) {
                result.put("error", "No function found with name '" + name + "'");
                return result;
            }
            String decompiled = decompileToC(target);
            result.put("name", target.getName());
            result.put("address", target.getEntryPoint().toString());
            result.put("decompiled", decompiled != null ? decompiled : "Decompilation failed");
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error decompiling function by name: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> disassembleFunction(String addressStr) {
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
            Listing listing = currentProgram.getListing();
            InstructionIterator instrIter = listing.getInstructions(function.getBody(), true);
            List<Map<String, Object>> instructions = new ArrayList<>();
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                Map<String, Object> instrInfo = new HashMap<>();
                instrInfo.put("address", instr.getAddress().toString());
                instrInfo.put("mnemonic", instr.getMnemonicString());
                instrInfo.put("text", instr.toString());
                instructions.add(instrInfo);
            }
            result.put("name", function.getName());
            result.put("address", function.getEntryPoint().toString());
            result.put("instructions", instructions);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error disassembling function: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> getFunctionByAddress(String addressStr) {
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
                function = functionManager.getFunctionContaining(address);
            }
            if (function == null) {
                result.put("error", "No function found at or containing address " + addressStr);
                return result;
            }
            result.put("name", function.getName());
            result.put("entry", function.getEntryPoint().toString());
            result.put("bodyStart", function.getBody().getMinAddress().toString());
            result.put("bodyEnd", function.getBody().getMaxAddress().toString());
            result.put("size", function.getBody().getNumAddresses());
            result.put("signature", function.getSignature().getPrototypeString());
            result.put("returnType", function.getReturnType().getName());
            result.put("callingConvention", function.getCallingConventionName());

            // Parameters
            List<Map<String, String>> params = new ArrayList<>();
            for (Variable param : function.getParameters()) {
                Map<String, String> p = new HashMap<>();
                p.put("name", param.getName());
                p.put("dataType", param.getDataType().getName());
                p.put("storage", param.getVariableStorage().toString());
                params.add(p);
            }
            result.put("parameters", params);

            // Callers (references to this function's entry point)
            ReferenceManager refManager = currentProgram.getReferenceManager();
            List<String> callers = new ArrayList<>();
            Iterator<Reference> refsTo = refManager.getReferencesTo(function.getEntryPoint());
            while (refsTo.hasNext()) {
                Reference ref = refsTo.next();
                Function caller = functionManager.getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    callers.add(caller.getName() + "@" + caller.getEntryPoint());
                }
            }
            result.put("callers", callers);

            // Callees (functions called by this function)
            List<String> callees = new ArrayList<>();
            Set<Function> calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            for (Function calledFunc : calledFunctions) {
                callees.add(calledFunc.getName() + "@" + calledFunc.getEntryPoint());
            }
            result.put("callees", callees);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting function by address: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> getCurrentAddress() {
        Map<String, Object> result = new HashMap<>();
        if (tool == null) {
            result.put("error", "PluginTool not available");
            return result;
        }
        try {
            CodeViewerService cvs = tool.getService(CodeViewerService.class);
            if (cvs == null) {
                result.put("error", "CodeViewerService not available");
                return result;
            }
            ProgramLocation loc = cvs.getCurrentLocation();
            if (loc == null) {
                result.put("error", "No current location");
                return result;
            }
            result.put("address", loc.getAddress().toString());
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting current address: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> getCurrentFunction() {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        if (tool == null) {
            result.put("error", "PluginTool not available");
            return result;
        }
        try {
            CodeViewerService cvs = tool.getService(CodeViewerService.class);
            if (cvs == null) {
                result.put("error", "CodeViewerService not available");
                return result;
            }
            ProgramLocation loc = cvs.getCurrentLocation();
            if (loc == null) {
                result.put("error", "No current location");
                return result;
            }
            Address addr = loc.getAddress();
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function function = functionManager.getFunctionContaining(addr);
            if (function == null) {
                result.put("error", "No function at current address " + addr.toString());
                return result;
            }
            result.put("name", function.getName());
            result.put("entry", function.getEntryPoint().toString());
            result.put("size", function.getBody().getNumAddresses());
            result.put("signature", function.getSignature().getPrototypeString());
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting current function: " + e.getMessage());
        }
        return result;
    }

    // --- 2.3 Cross-Reference Methods ---

    public Map<String, Object> getXrefsTo(String addressStr, int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            Address address = currentProgram.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = currentProgram.getReferenceManager();
            FunctionManager functionManager = currentProgram.getFunctionManager();
            List<Map<String, Object>> refs = new ArrayList<>();
            Iterator<Reference> refIter = refManager.getReferencesTo(address);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", ref.getFromAddress().toString());
                refInfo.put("toAddress", ref.getToAddress().toString());
                refInfo.put("refType", ref.getReferenceType().getName());
                refInfo.put("isCall", ref.getReferenceType().isCall());
                Function fromFunc = functionManager.getFunctionContaining(ref.getFromAddress());
                refInfo.put("fromFunction", fromFunc != null ? fromFunc.getName() : null);
                refs.add(refInfo);
            }
            result.putAll(paginate(refs, offset, limit));
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting xrefs to: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> getXrefsFrom(String addressStr, int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            Address address = currentProgram.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = currentProgram.getReferenceManager();
            FunctionManager functionManager = currentProgram.getFunctionManager();
            List<Map<String, Object>> refs = new ArrayList<>();
            Reference[] refsFrom = refManager.getReferencesFrom(address);
            for (Reference ref : refsFrom) {
                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", ref.getFromAddress().toString());
                refInfo.put("toAddress", ref.getToAddress().toString());
                refInfo.put("refType", ref.getReferenceType().getName());
                refInfo.put("isCall", ref.getReferenceType().isCall());
                Function toFunc = functionManager.getFunctionContaining(ref.getToAddress());
                refInfo.put("toFunction", toFunc != null ? toFunc.getName() : null);
                refs.add(refInfo);
            }
            result.putAll(paginate(refs, offset, limit));
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting xrefs from: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> getFunctionXrefs(String functionName, int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Iterator<Function> funcIter = functionManager.getFunctions(true);
            Function target = null;
            while (funcIter.hasNext()) {
                Function f = funcIter.next();
                if (f.getName().equals(functionName)) {
                    target = f;
                    break;
                }
            }
            if (target == null) {
                result.put("error", "No function found with name '" + functionName + "'");
                return result;
            }
            ReferenceManager refManager = currentProgram.getReferenceManager();
            List<Map<String, Object>> refs = new ArrayList<>();
            Iterator<Reference> refIter = refManager.getReferencesTo(target.getEntryPoint());
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", ref.getFromAddress().toString());
                refInfo.put("toAddress", ref.getToAddress().toString());
                refInfo.put("refType", ref.getReferenceType().getName());
                refInfo.put("isCall", ref.getReferenceType().isCall());
                Function fromFunc = functionManager.getFunctionContaining(ref.getFromAddress());
                refInfo.put("fromFunction", fromFunc != null ? fromFunc.getName() : null);
                refs.add(refInfo);
            }
            result.put("function", target.getName());
            result.put("functionAddress", target.getEntryPoint().toString());
            result.putAll(paginate(refs, offset, limit));
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting function xrefs: " + e.getMessage());
        }
        return result;
    }

    // --- 2.4 Comment Methods ---

    public Map<String, Object> setDecompilerComment(String addressStr, String comment) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Decompiler Comment");
                try {
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    Listing listing = currentProgram.getListing();
                    CodeUnit cu = listing.getCodeUnitAt(addr);
                    if (cu == null) {
                        result.put("error", "No code unit at address " + addressStr);
                        return;
                    }
                    cu.setComment(CommentType.PRE, comment);
                    result.put("success", true);
                    result.put("address", addressStr);
                    result.put("comment", comment);
                } catch (Exception e) {
                    result.put("error", "Error setting comment: " + e.getMessage());
                    Msg.error(this, "Error setting decompiler comment: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> setDisassemblyComment(String addressStr, String comment) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Disassembly Comment");
                try {
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    Listing listing = currentProgram.getListing();
                    CodeUnit cu = listing.getCodeUnitAt(addr);
                    if (cu == null) {
                        result.put("error", "No code unit at address " + addressStr);
                        return;
                    }
                    cu.setComment(CommentType.EOL, comment);
                    result.put("success", true);
                    result.put("address", addressStr);
                    result.put("comment", comment);
                } catch (Exception e) {
                    result.put("error", "Error setting comment: " + e.getMessage());
                    Msg.error(this, "Error setting disassembly comment: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.5 Type System ---

    private DataType resolveDataType(String typeName) {
        if (typeName == null || typeName.trim().isEmpty()) {
            return null;
        }
        typeName = typeName.trim();
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // 1. Exact path match
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) {
            return dt;
        }

        // 2. P-prefix pointer types (Windows convention)
        if (typeName.startsWith("P") && typeName.length() > 1 && Character.isUpperCase(typeName.charAt(1))) {
            String baseTypeName = typeName.substring(1);
            DataType baseType = resolveDataType(baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
        }

        // 3. Pointer handling: "type *" or "type*"
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();
            DataType baseType = resolveDataType(baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
        }

        // 4. Common C built-ins
        switch (typeName.toLowerCase()) {
            case "int":
                return IntegerDataType.dataType;
            case "char":
                return CharDataType.dataType;
            case "void":
                return VoidDataType.dataType;
            case "bool":
            case "boolean":
            case "_bool":
                return BooleanDataType.dataType;
            case "float":
                return FloatDataType.dataType;
            case "double":
                return DoubleDataType.dataType;
            case "long":
                return LongDataType.dataType;
            case "short":
                return ShortDataType.dataType;
            case "byte":
            case "uint8_t":
            case "uchar":
            case "unsigned char":
                return ByteDataType.dataType;
            case "uint":
            case "uint32_t":
            case "unsigned int":
            case "unsigned":
            case "dword":
                return UnsignedIntegerDataType.dataType;
            case "ushort":
            case "uint16_t":
            case "unsigned short":
            case "word":
                return UnsignedShortDataType.dataType;
            case "uint64_t":
            case "unsigned long long":
            case "ulonglong":
            case "qword":
                return UnsignedLongLongDataType.dataType;
            case "pointer":
            case "void*":
            case "void *":
            case "ptr":
            case "pvoid":
            case "lpvoid":
                return PointerDataType.dataType;
            case "long long":
            case "int64_t":
            case "longlong":
                return LongLongDataType.dataType;
            case "undefined":
                return Undefined1DataType.dataType;
            case "undefined1":
                return Undefined1DataType.dataType;
            case "undefined2":
                return Undefined2DataType.dataType;
            case "undefined4":
                return Undefined4DataType.dataType;
            case "undefined8":
                return Undefined8DataType.dataType;
            case "string":
                return StringDataType.dataType;
        }

        // 5. Search by name
        ArrayList<DataType> results = new ArrayList<>();
        dtm.findDataTypes(typeName, results);
        if (!results.isEmpty()) {
            return results.get(0);
        }

        // 6. Also search in built-in data type manager
        BuiltInDataTypeManager builtInDtm = BuiltInDataTypeManager.getDataTypeManager();
        if (builtInDtm != null) {
            results.clear();
            builtInDtm.findDataTypes(typeName, results);
            if (!results.isEmpty()) {
                return results.get(0);
            }
        }

        return null;
    }

    // --- 2.6 Function Prototype ---

    public Map<String, Object> setFunctionPrototype(String functionAddress, String prototype) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Function Prototype");
                try {
                    Address entryAddr = currentProgram.getAddressFactory().getAddress(functionAddress);
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Function function = functionManager.getFunctionAt(entryAddr);
                    if (function == null) {
                        result.put("error", "No function found at address " + functionAddress);
                        return;
                    }
                    String oldPrototype = function.getSignature().getPrototypeString();
                    FunctionSignatureParser parser = new FunctionSignatureParser(
                        currentProgram.getDataTypeManager(), null);
                    FunctionDefinitionDataType parsedSig =
                        parser.parse(null, prototype);
                    ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                        entryAddr, parsedSig, SourceType.USER_DEFINED);
                    boolean applied = cmd.applyTo(currentProgram, TaskMonitor.DUMMY);
                    if (applied) {
                        result.put("success", true);
                        result.put("function", function.getName());
                        result.put("oldPrototype", oldPrototype);
                        result.put("newPrototype", prototype);
                    } else {
                        result.put("error", "Failed to apply function signature: " + cmd.getStatusMsg());
                    }
                } catch (Exception e) {
                    result.put("error", "Error setting prototype: " + e.getMessage());
                    Msg.error(this, "Error setting function prototype: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.7 Variable Type Change ---

    public Map<String, Object> setLocalVariableType(String functionAddress, String variableName, String newType) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Variable Type");
                DecompInterface decomp = new DecompInterface();
                try {
                    Address entryAddr = currentProgram.getAddressFactory().getAddress(functionAddress);
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Function function = functionManager.getFunctionAt(entryAddr);
                    if (function == null) {
                        result.put("error", "No function found at address " + functionAddress);
                        return;
                    }
                    DataType resolvedType = resolveDataType(newType);
                    if (resolvedType == null) {
                        result.put("error", "Could not resolve data type: " + newType);
                        return;
                    }
                    // First check parameters and locals directly
                    Variable targetVar = null;
                    String oldType = null;
                    for (Variable param : function.getParameters()) {
                        if (param.getName().equals(variableName)) {
                            targetVar = param;
                            oldType = param.getDataType().getName();
                            break;
                        }
                    }
                    if (targetVar == null) {
                        for (Variable local : function.getLocalVariables()) {
                            if (local.getName().equals(variableName)) {
                                targetVar = local;
                                oldType = local.getDataType().getName();
                                break;
                            }
                        }
                    }
                    if (targetVar != null) {
                        targetVar.setDataType(resolvedType, SourceType.USER_DEFINED);
                        result.put("success", true);
                        result.put("function", function.getName());
                        result.put("variable", variableName);
                        result.put("oldType", oldType);
                        result.put("newType", resolvedType.getName());
                    } else {
                        // Try decompiler high variables
                        decomp.openProgram(currentProgram);
                        DecompileResults decompResults = decomp.decompileFunction(function, DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
                        if (decompResults.decompileCompleted()) {
                            HighFunction highFunc = decompResults.getHighFunction();
                            if (highFunc != null) {
                                LocalSymbolMap localSymbolMap = highFunc.getLocalSymbolMap();
                                Iterator<HighSymbol> symIter = localSymbolMap.getSymbols();
                                boolean found = false;
                                while (symIter.hasNext()) {
                                    HighSymbol sym = symIter.next();
                                    if (sym.getName().equals(variableName)) {
                                        oldType = sym.getDataType().getName();
                                        HighFunctionDBUtil.updateDBVariable(sym,
                                            variableName, resolvedType, SourceType.USER_DEFINED);
                                        result.put("success", true);
                                        result.put("function", function.getName());
                                        result.put("variable", variableName);
                                        result.put("oldType", oldType);
                                        result.put("newType", resolvedType.getName());
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    result.put("error", "Variable '" + variableName + "' not found");
                                }
                            } else {
                                result.put("error", "Decompilation did not produce high function");
                            }
                        } else {
                            result.put("error", "Decompilation failed");
                        }
                    }
                } catch (Exception e) {
                    result.put("error", "Error setting variable type: " + e.getMessage());
                    Msg.error(this, "Error setting variable type: " + e.getMessage());
                } finally {
                    decomp.dispose();
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.8 Bookmark Methods ---

    public Map<String, Object> setBookmark(String addressStr, String type, String category, String comment) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Bookmark");
                try {
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
                    bookmarkManager.setBookmark(addr, type, category, comment);
                    result.put("success", true);
                    result.put("address", addressStr);
                } catch (Exception e) {
                    result.put("error", "Error setting bookmark: " + e.getMessage());
                    Msg.error(this, "Error setting bookmark: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> getBookmarks(String addressStr) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
            Bookmark[] bookmarks = bookmarkManager.getBookmarks(addr);
            List<Map<String, Object>> bookmarkList = new ArrayList<>();
            for (Bookmark bm : bookmarks) {
                Map<String, Object> bmInfo = new HashMap<>();
                bmInfo.put("type", bm.getTypeString());
                bmInfo.put("category", bm.getCategory());
                bmInfo.put("comment", bm.getComment());
                bmInfo.put("address", bm.getAddress().toString());
                bookmarkList.add(bmInfo);
            }
            result.put("bookmarks", bookmarkList);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting bookmarks: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> removeBookmark(String addressStr, String type, String category) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Remove Bookmark");
                try {
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
                    Bookmark[] bookmarks = bookmarkManager.getBookmarks(addr);
                    boolean found = false;
                    for (Bookmark bm : bookmarks) {
                        if (bm.getTypeString().equals(type) && bm.getCategory().equals(category)) {
                            bookmarkManager.removeBookmark(bm);
                            found = true;
                            break;
                        }
                    }
                    if (found) {
                        result.put("success", true);
                    } else {
                        result.put("error", "No bookmark with type '" + type + "' and category '" + category + "' at " + addressStr);
                    }
                } catch (Exception e) {
                    result.put("error", "Error removing bookmark: " + e.getMessage());
                    Msg.error(this, "Error removing bookmark: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.9 Equate Methods ---

    public Map<String, Object> setEquate(String addressStr, int operandIndex, String name, long value) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Equate");
                try {
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    EquateTable equateTable = currentProgram.getEquateTable();
                    Equate equate = equateTable.getEquate(name);
                    if (equate == null) {
                        equate = equateTable.createEquate(name, value);
                    }
                    equate.addReference(addr, operandIndex);
                    result.put("success", true);
                    result.put("name", name);
                    result.put("value", value);
                    result.put("address", addressStr);
                } catch (Exception e) {
                    result.put("error", "Error setting equate: " + e.getMessage());
                    Msg.error(this, "Error setting equate: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> listEquates() {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            EquateTable equateTable = currentProgram.getEquateTable();
            List<Map<String, Object>> equates = new ArrayList<>();
            Iterator<Equate> eqIter = equateTable.getEquates();
            while (eqIter.hasNext()) {
                Equate eq = eqIter.next();
                Map<String, Object> eqInfo = new HashMap<>();
                eqInfo.put("name", eq.getName());
                eqInfo.put("value", eq.getValue());
                eqInfo.put("referenceCount", eq.getReferenceCount());
                equates.add(eqInfo);
            }
            result.put("equates", equates);
            result.put("count", equates.size());
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error listing equates: " + e.getMessage());
        }
        return result;
    }

    // --- 2.10 Structure/Enum Creation ---

    public Map<String, Object> createStructure(String name, List<Map<String, Object>> fields) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Create Structure");
                try {
                    DataTypeManager dtm = currentProgram.getDataTypeManager();
                    StructureDataType struct = new StructureDataType(name, 0);
                    for (Map<String, Object> field : fields) {
                        String fieldName = (String) field.get("name");
                        String fieldTypeName = (String) field.get("type");
                        int fieldSize = field.containsKey("size") ? ((Number) field.get("size")).intValue() : 0;
                        DataType fieldType = resolveDataType(fieldTypeName);
                        if (fieldType == null) {
                            result.put("error", "Could not resolve field type: " + fieldTypeName);
                            return;
                        }
                        struct.add(fieldType, fieldSize > 0 ? fieldSize : fieldType.getLength(), fieldName, null);
                    }
                    dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
                    result.put("success", true);
                    result.put("name", name);
                    result.put("size", struct.getLength());
                    result.put("fieldCount", fields.size());
                } catch (Exception e) {
                    result.put("error", "Error creating structure: " + e.getMessage());
                    Msg.error(this, "Error creating structure: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.10b Structure CRUD ---

    /**
     * Get detailed information about a structure by name.
     */
    public Map<String, Object> getStructure(String name) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        ArrayList<DataType> found = new ArrayList<>();
        dtm.findDataTypes(name, found);
        Structure struct = null;
        for (DataType dt : found) {
            if (dt instanceof Structure) {
                struct = (Structure) dt;
                break;
            }
        }
        if (struct == null) {
            result.put("error", "Structure not found: " + name);
            return result;
        }
        result.put("name", struct.getName());
        result.put("size", struct.getLength());
        result.put("categoryPath", struct.getCategoryPath().getPath());
        result.put("alignment", struct.getAlignment());
        result.put("description", struct.getDescription() != null ? struct.getDescription() : "");
        List<Map<String, Object>> fieldList = new ArrayList<>();
        for (DataTypeComponent comp : struct.getComponents()) {
            Map<String, Object> field = new HashMap<>();
            field.put("ordinal", comp.getOrdinal());
            field.put("offset", comp.getOffset());
            field.put("length", comp.getLength());
            field.put("fieldName", comp.getFieldName() != null ? comp.getFieldName() : "");
            field.put("dataType", comp.getDataType().getName());
            field.put("comment", comp.getComment() != null ? comp.getComment() : "");
            fieldList.add(field);
        }
        result.put("fields", fieldList);
        result.put("fieldCount", fieldList.size());
        return result;
    }

    /**
     * List all structure data types with pagination.
     */
    public Map<String, Object> listStructures(int offset, int limit) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        List<Map<String, Object>> structures = new ArrayList<>();
        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (dt instanceof Structure) {
                Structure s = (Structure) dt;
                Map<String, Object> info = new HashMap<>();
                info.put("name", s.getName());
                info.put("size", s.getLength());
                info.put("fieldCount", s.getNumComponents());
                info.put("categoryPath", s.getCategoryPath().getPath());
                structures.add(info);
            }
        }
        result.putAll(paginate(structures, offset, limit));
        return result;
    }

    /**
     * Edit a structure's fields using a list of operations.
     * Supported actions: add, insert, delete, replace, clear.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> editStructure(String name, List<Map<String, Object>> operations) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Edit Structure");
                try {
                    DataTypeManager dtm = currentProgram.getDataTypeManager();
                    ArrayList<DataType> found = new ArrayList<>();
                    dtm.findDataTypes(name, found);
                    Structure struct = null;
                    for (DataType dt : found) {
                        if (dt instanceof Structure) {
                            struct = (Structure) dt;
                            break;
                        }
                    }
                    if (struct == null) {
                        result.put("error", "Structure not found: " + name);
                        return;
                    }
                    int opsApplied = 0;
                    for (Map<String, Object> op : operations) {
                        String action = (String) op.get("action");
                        if (action == null) {
                            continue;
                        }
                        switch (action) {
                            case "add": {
                                String fieldName = (String) op.get("name");
                                String typeName = (String) op.get("type");
                                int size = op.containsKey("size") ? ((Number) op.get("size")).intValue() : 0;
                                String comment = (String) op.get("comment");
                                DataType fieldType = resolveDataType(typeName);
                                if (fieldType == null) {
                                    result.put("error", "Cannot resolve type: " + typeName);
                                    return;
                                }
                                struct.add(fieldType, size > 0 ? size : fieldType.getLength(), fieldName, comment);
                                opsApplied++;
                                break;
                            }
                            case "insert": {
                                int offset1 = ((Number) op.get("offset")).intValue();
                                String fieldName = (String) op.get("name");
                                String typeName = (String) op.get("type");
                                int size = op.containsKey("size") ? ((Number) op.get("size")).intValue() : 0;
                                String comment = (String) op.get("comment");
                                DataType fieldType = resolveDataType(typeName);
                                if (fieldType == null) {
                                    result.put("error", "Cannot resolve type: " + typeName);
                                    return;
                                }
                                struct.insertAtOffset(offset1, fieldType, size > 0 ? size : fieldType.getLength(), fieldName, comment);
                                opsApplied++;
                                break;
                            }
                            case "delete": {
                                int delOffset = ((Number) op.get("offset")).intValue();
                                int delSize = ((Number) op.get("size")).intValue();
                                struct.deleteAtOffset(delOffset);
                                opsApplied++;
                                break;
                            }
                            case "replace": {
                                int repOffset = ((Number) op.get("offset")).intValue();
                                String fieldName = (String) op.get("name");
                                String typeName = (String) op.get("type");
                                int size = op.containsKey("size") ? ((Number) op.get("size")).intValue() : 0;
                                String comment = (String) op.get("comment");
                                DataType fieldType = resolveDataType(typeName);
                                if (fieldType == null) {
                                    result.put("error", "Cannot resolve type: " + typeName);
                                    return;
                                }
                                struct.replaceAtOffset(repOffset, fieldType, size > 0 ? size : fieldType.getLength(), fieldName, comment);
                                opsApplied++;
                                break;
                            }
                            case "clear": {
                                int ordinal = ((Number) op.get("ordinal")).intValue();
                                struct.clearComponent(ordinal);
                                opsApplied++;
                                break;
                            }
                            default:
                                result.put("error", "Unknown action: " + action);
                                return;
                        }
                    }
                    result.put("success", true);
                    result.put("operationsApplied", opsApplied);
                    result.put("newSize", struct.getLength());
                    result.put("newFieldCount", struct.getNumComponents());
                } catch (Exception e) {
                    result.put("error", "Error editing structure: " + e.getMessage());
                    Msg.error(this, "Error editing structure: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    /**
     * Rename a structure data type.
     */
    public Map<String, Object> renameStructure(String currentName, String newName) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Rename Structure");
                try {
                    DataTypeManager dtm = currentProgram.getDataTypeManager();
                    ArrayList<DataType> found = new ArrayList<>();
                    dtm.findDataTypes(currentName, found);
                    Structure struct = null;
                    for (DataType dt : found) {
                        if (dt instanceof Structure) {
                            struct = (Structure) dt;
                            break;
                        }
                    }
                    if (struct == null) {
                        result.put("error", "Structure not found: " + currentName);
                        return;
                    }
                    struct.setName(newName);
                    result.put("success", true);
                    result.put("oldName", currentName);
                    result.put("newName", newName);
                } catch (Exception e) {
                    result.put("error", "Error renaming structure: " + e.getMessage());
                    Msg.error(this, "Error renaming structure: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    /**
     * Delete a structure data type.
     */
    public Map<String, Object> deleteStructure(String name) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Delete Structure");
                try {
                    DataTypeManager dtm = currentProgram.getDataTypeManager();
                    ArrayList<DataType> found = new ArrayList<>();
                    dtm.findDataTypes(name, found);
                    Structure struct = null;
                    for (DataType dt : found) {
                        if (dt instanceof Structure) {
                            struct = (Structure) dt;
                            break;
                        }
                    }
                    if (struct == null) {
                        result.put("error", "Structure not found: " + name);
                        return;
                    }
                    dtm.remove(struct);
                    result.put("success", true);
                    result.put("deletedName", name);
                } catch (Exception e) {
                    result.put("error", "Error deleting structure: " + e.getMessage());
                    Msg.error(this, "Error deleting structure: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> createEnum(String name, int size, Map<String, Long> values) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Create Enum");
                try {
                    DataTypeManager dtm = currentProgram.getDataTypeManager();
                    EnumDataType enumDt = new EnumDataType(name, size);
                    for (Map.Entry<String, Long> entry : values.entrySet()) {
                        enumDt.add(entry.getKey(), entry.getValue());
                    }
                    dtm.addDataType(enumDt, DataTypeConflictHandler.DEFAULT_HANDLER);
                    result.put("success", true);
                    result.put("name", name);
                    result.put("size", size);
                    result.put("valueCount", values.size());
                } catch (Exception e) {
                    result.put("error", "Error creating enum: " + e.getMessage());
                    Msg.error(this, "Error creating enum: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.11 Data Type Application ---

    public Map<String, Object> applyDataType(String addressStr, String typeName) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Apply Data Type");
                try {
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    DataType dt = resolveDataType(typeName);
                    if (dt == null) {
                        result.put("error", "Could not resolve data type: " + typeName);
                        return;
                    }
                    DataUtilities.createData(currentProgram, addr, dt, -1, false,
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    result.put("success", true);
                    result.put("address", addressStr);
                    result.put("type", dt.getName());
                } catch (Exception e) {
                    result.put("error", "Error applying data type: " + e.getMessage());
                    Msg.error(this, "Error applying data type: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.12 Patch Bytes ---

    public Map<String, Object> patchBytes(String addressStr, String hexBytes) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Patch Bytes");
                try {
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    String cleanHex = hexBytes.replaceAll("\\s+", "");
                    if (cleanHex.length() > 16384) {
                        result.put("error", "Patch size exceeds maximum of 8192 bytes");
                        return;
                    }
                    if (cleanHex.length() % 2 != 0) {
                        result.put("error", "Hex string must have even length");
                        return;
                    }
                    byte[] bytes = new byte[cleanHex.length() / 2];
                    for (int i = 0; i < bytes.length; i++) {
                        bytes[i] = (byte) Integer.parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
                    }
                    Memory memory = currentProgram.getMemory();
                    memory.setBytes(addr, bytes);
                    result.put("success", true);
                    result.put("address", addressStr);
                    result.put("bytesWritten", bytes.length);
                } catch (Exception e) {
                    result.put("error", "Error patching bytes: " + e.getMessage());
                    Msg.error(this, "Error patching bytes: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.13 Basic Blocks ---

    public Map<String, Object> getBasicBlocks(String functionAddress) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            Address entryAddr = currentProgram.getAddressFactory().getAddress(functionAddress);
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function function = functionManager.getFunctionAt(entryAddr);
            if (function == null) {
                result.put("error", "No function found at address " + functionAddress);
                return result;
            }
            BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
            CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(function.getBody(), TaskMonitor.DUMMY);
            List<Map<String, Object>> blocks = new ArrayList<>();
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                Map<String, Object> blockInfo = new HashMap<>();
                blockInfo.put("start", block.getMinAddress().toString());
                blockInfo.put("end", block.getMaxAddress().toString());
                List<String> successors = new ArrayList<>();
                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    CodeBlockReference destRef = destIter.next();
                    successors.add(destRef.getDestinationAddress().toString());
                }
                blockInfo.put("successors", successors);
                blocks.add(blockInfo);
            }
            result.put("function", function.getName());
            result.put("blocks", blocks);
            result.put("blockCount", blocks.size());
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting basic blocks: " + e.getMessage());
        }
        return result;
    }

    // --- 2.14 Security Analysis - searchBytes ---

    public Map<String, Object> searchBytes(String pattern, String mask, String startAddress, int maxResults) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            String cleanPattern = pattern.replaceAll("\\s+", "");
            if (cleanPattern.length() % 2 != 0) {
                result.put("error", "Pattern hex string must have even length");
                return result;
            }
            byte[] patternBytes = new byte[cleanPattern.length() / 2];
            for (int i = 0; i < patternBytes.length; i++) {
                patternBytes[i] = (byte) Integer.parseInt(cleanPattern.substring(i * 2, i * 2 + 2), 16);
            }
            byte[] maskBytes = null;
            if (mask != null && !mask.trim().isEmpty()) {
                String cleanMask = mask.replaceAll("\\s+", "");
                if (cleanMask.length() % 2 != 0) {
                    result.put("error", "Mask hex string must have even length");
                    return result;
                }
                maskBytes = new byte[cleanMask.length() / 2];
                for (int i = 0; i < maskBytes.length; i++) {
                    maskBytes[i] = (byte) Integer.parseInt(cleanMask.substring(i * 2, i * 2 + 2), 16);
                }
            }
            Memory memory = currentProgram.getMemory();
            Address searchAddr;
            if (startAddress != null && !startAddress.trim().isEmpty()) {
                searchAddr = currentProgram.getAddressFactory().getAddress(startAddress);
            } else {
                searchAddr = memory.getMinAddress();
            }
            List<Map<String, Object>> matches = new ArrayList<>();
            int count = 0;
            while (searchAddr != null && count < maxResults) {
                Address found = memory.findBytes(searchAddr, patternBytes, maskBytes, true, TaskMonitor.DUMMY);
                if (found == null) {
                    break;
                }
                Map<String, Object> matchInfo = new HashMap<>();
                matchInfo.put("address", found.toString());
                FunctionManager functionManager = currentProgram.getFunctionManager();
                Function containingFunc = functionManager.getFunctionContaining(found);
                if (containingFunc != null) {
                    matchInfo.put("function", containingFunc.getName());
                }
                matches.add(matchInfo);
                count++;
                try {
                    searchAddr = found.add(1);
                } catch (Exception e) {
                    break;
                }
            }
            result.put("matches", matches);
            result.put("count", matches.size());
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error searching bytes: " + e.getMessage());
        }
        return result;
    }

    // --- 2.15 Security Analysis - extractIOCs ---

    public Map<String, Object> extractIOCs() {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            List<String> urls = new ArrayList<>();
            List<String> ips = new ArrayList<>();
            List<String> domains = new ArrayList<>();
            List<String> filePaths = new ArrayList<>();
            List<String> registryKeys = new ArrayList<>();
            List<String> emails = new ArrayList<>();

            Pattern urlPattern = Pattern.compile("https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+", Pattern.CASE_INSENSITIVE);
            Pattern ipPattern = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
            Pattern domainPattern = Pattern.compile("\\b(?:[a-zA-Z0-9\\-]+\\.)+(?:com|net|org|io|gov|edu|mil|info|biz|co|uk|de|ru|cn|jp|br|au|in|fr)\\b", Pattern.CASE_INSENSITIVE);
            Pattern filePathPattern = Pattern.compile("(?:[A-Za-z]:\\\\[\\w\\\\. \\-]+|/(?:usr|etc|var|tmp|home|opt|bin|sbin|lib)[/\\w.\\- ]*)", Pattern.CASE_INSENSITIVE);
            Pattern registryKeyPattern = Pattern.compile("(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\\\[\\w\\\\. \\-]+", Pattern.CASE_INSENSITIVE);
            Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", Pattern.CASE_INSENSITIVE);

            Set<String> seenUrls = new HashSet<>();
            Set<String> seenIps = new HashSet<>();
            Set<String> seenDomains = new HashSet<>();
            Set<String> seenPaths = new HashSet<>();
            Set<String> seenRegKeys = new HashSet<>();
            Set<String> seenEmails = new HashSet<>();

            DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                String typeName = data.getDataType().getName().toLowerCase();
                if (typeName.contains("string") || typeName.contains("unicode") ||
                    (typeName.contains("char") && typeName.contains("["))) {
                    String value = data.getDefaultValueRepresentation();
                    if (value == null || value.length() < 4) continue;
                    // Remove surrounding quotes if present
                    if (value.startsWith("\"") && value.endsWith("\"")) {
                        value = value.substring(1, value.length() - 1);
                    }
                    Matcher m;
                    m = urlPattern.matcher(value);
                    while (m.find()) { String v = m.group(); if (seenUrls.add(v)) urls.add(v); }
                    m = ipPattern.matcher(value);
                    while (m.find()) {
                        String v = m.group();
                        // Validate IP octets
                        String[] octets = v.split("\\.");
                        boolean valid = true;
                        for (String octet : octets) {
                            int val = Integer.parseInt(octet);
                            if (val < 0 || val > 255) { valid = false; break; }
                        }
                        if (valid && seenIps.add(v)) ips.add(v);
                    }
                    m = domainPattern.matcher(value);
                    while (m.find()) { String v = m.group(); if (seenDomains.add(v)) domains.add(v); }
                    m = filePathPattern.matcher(value);
                    while (m.find()) { String v = m.group(); if (seenPaths.add(v)) filePaths.add(v); }
                    m = registryKeyPattern.matcher(value);
                    while (m.find()) { String v = m.group(); if (seenRegKeys.add(v)) registryKeys.add(v); }
                    m = emailPattern.matcher(value);
                    while (m.find()) { String v = m.group(); if (seenEmails.add(v)) emails.add(v); }
                }
            }
            result.put("urls", urls);
            result.put("ips", ips);
            result.put("domains", domains);
            result.put("filePaths", filePaths);
            result.put("registryKeys", registryKeys);
            result.put("emails", emails);
            result.put("total", urls.size() + ips.size() + domains.size() + filePaths.size() + registryKeys.size() + emails.size());
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error extracting IOCs: " + e.getMessage());
        }
        return result;
    }

    // --- 2.16 Security Analysis - detectAntiAnalysis ---

    public Map<String, Object> detectAntiAnalysis() {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            List<Map<String, Object>> findings = new ArrayList<>();
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            FunctionManager functionManager = currentProgram.getFunctionManager();
            ReferenceManager refManager = currentProgram.getReferenceManager();

            // Anti-debug APIs
            String[][] antiDebugAPIs = {
                {"IsDebuggerPresent", "anti-debug", "Debugger detection via API", "high"},
                {"CheckRemoteDebuggerPresent", "anti-debug", "Remote debugger detection", "high"},
                {"NtQueryInformationProcess", "anti-debug", "Process information query (debug flags)", "high"},
                {"OutputDebugString", "anti-debug", "Debug string output (timing check)", "medium"},
                {"FindWindow", "anti-debug", "Window detection (debugger UI)", "medium"},
                {"GetTickCount", "anti-debug", "Timing check", "medium"},
                {"QueryPerformanceCounter", "anti-debug", "High-resolution timing check", "medium"},
                {"rdtsc", "anti-debug", "RDTSC timing check", "high"},
                {"NtSetInformationThread", "anti-debug", "Thread hiding from debugger", "high"},
                {"ZwSetInformationThread", "anti-debug", "Thread hiding from debugger", "high"},
            };
            // Anti-VM APIs
            String[][] antiVmAPIs = {
                {"GetSystemFirmwareTable", "anti-vm", "Firmware table check", "high"},
                {"EnumDeviceDrivers", "anti-vm", "Device driver enumeration", "medium"},
                {"CreateToolhelp32Snapshot", "anti-vm", "Process snapshot (VM process check)", "low"},
                {"GetAdaptersInfo", "anti-vm", "Network adapter check (VM MAC)", "medium"},
                {"GetDiskFreeSpaceEx", "anti-vm", "Disk space check", "low"},
            };
            // Anti-sandbox APIs
            String[][] antiSandboxAPIs = {
                {"GetCursorPos", "anti-sandbox", "Cursor position check", "medium"},
                {"GetForegroundWindow", "anti-sandbox", "Foreground window check", "low"},
                {"GetSystemMetrics", "anti-sandbox", "System metrics check", "low"},
                {"GlobalMemoryStatusEx", "anti-sandbox", "Memory size check", "medium"},
                {"GetSystemInfo", "anti-sandbox", "System info check (CPU count)", "medium"},
                {"Sleep", "anti-sandbox", "Sleep-based evasion", "low"},
            };

            String[][][] allAPIs = {antiDebugAPIs, antiVmAPIs, antiSandboxAPIs};
            for (String[][] apiGroup : allAPIs) {
                for (String[] apiInfo : apiGroup) {
                    String apiName = apiInfo[0];
                    String type = apiInfo[1];
                    String technique = apiInfo[2];
                    String confidence = apiInfo[3];
                    SymbolIterator symbols = symbolTable.getSymbols(apiName);
                    while (symbols.hasNext()) {
                        Symbol symbol = symbols.next();
                        Iterator<Reference> refs = refManager.getReferencesTo(symbol.getAddress());
                        while (refs.hasNext()) {
                            Reference ref = refs.next();
                            Map<String, Object> finding = new HashMap<>();
                            finding.put("type", type);
                            finding.put("technique", technique);
                            finding.put("api", apiName);
                            finding.put("address", ref.getFromAddress().toString());
                            finding.put("confidence", confidence);
                            Function callerFunc = functionManager.getFunctionContaining(ref.getFromAddress());
                            if (callerFunc != null) {
                                finding.put("function", callerFunc.getName());
                            }
                            findings.add(finding);
                        }
                    }
                }
            }

            // Check for int 2d (anti-debug interrupt)
            Memory memory = currentProgram.getMemory();
            byte[] int2d = {(byte) 0xCD, (byte) 0x2D};
            Address searchAddr = memory.getMinAddress();
            while (searchAddr != null) {
                Address found = memory.findBytes(searchAddr, int2d, null, true, TaskMonitor.DUMMY);
                if (found == null) break;
                Map<String, Object> finding = new HashMap<>();
                finding.put("type", "anti-debug");
                finding.put("technique", "INT 2D instruction");
                finding.put("address", found.toString());
                finding.put("confidence", "high");
                Function func = functionManager.getFunctionContaining(found);
                if (func != null) finding.put("function", func.getName());
                findings.add(finding);
                try { searchAddr = found.add(2); } catch (Exception e) { break; }
            }

            result.put("findings", findings);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error detecting anti-analysis: " + e.getMessage());
        }
        return result;
    }

    // --- 2.17 Security Analysis - addExternalFunction ---

    public Map<String, Object> addExternalFunction(String library, String functionName, String addressStr) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Add External Function");
                try {
                    ExternalManager extManager = currentProgram.getExternalManager();
                    Address addr = null;
                    if (addressStr != null && !addressStr.trim().isEmpty()) {
                        addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    }
                    if (!extManager.contains(library)) {
                        extManager.addExternalLibraryName(library, SourceType.USER_DEFINED);
                    }
                    extManager.addExtFunction(library, functionName, addr, SourceType.USER_DEFINED);
                    result.put("success", true);
                    result.put("library", library);
                    result.put("function", functionName);
                    result.put("address", addressStr);
                } catch (Exception e) {
                    result.put("error", "Error adding external function: " + e.getMessage());
                    Msg.error(this, "Error adding external function: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.18 Security Analysis - Binary Info ---

    /**
     * Get binary metadata (format, sections, entry points, etc).
     * Works for PE, ELF, Mach-O, and any other format Ghidra supports.
     */
    private Map<String, Object> getBinaryInfo() {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            result.put("format", currentProgram.getExecutableFormat());
            result.put("imageBase", currentProgram.getImageBase().toString());
            result.put("language", currentProgram.getLanguage().getLanguageID().getIdAsString());
            result.put("processor", currentProgram.getLanguage().getProcessor().toString());
            result.put("endian", currentProgram.getLanguage().isBigEndian() ? "big" : "little");
            result.put("pointerSize", currentProgram.getDefaultPointerSize());
            result.put("compiler", currentProgram.getCompiler());

            // Entry points
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
            List<String> entryPtList = new ArrayList<>();
            while (entryPoints.hasNext()) {
                entryPtList.add(entryPoints.next().toString());
            }
            result.put("entryPoints", entryPtList);

            // Sections / memory blocks
            Memory memory = currentProgram.getMemory();
            List<Map<String, Object>> sections = new ArrayList<>();
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

            // Program metadata properties
            Map<String, String> metadata = new HashMap<>();
            ghidra.framework.options.Options propList = currentProgram.getOptions("Program Information");
            for (String optName : propList.getOptionNames()) {
                try {
                    String val = propList.getValueAsString(optName);
                    if (val != null) {
                        metadata.put(optName, val);
                    }
                } catch (Exception e) {
                    // skip non-string properties
                }
            }
            result.put("metadata", metadata);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error getting binary info: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> getPEInfo() {
        return getBinaryInfo();
    }

    public Map<String, Object> getELFInfo() {
        return getBinaryInfo();
    }

    // --- 2.19 IoT Tools - setImageBase ---

    public Map<String, Object> setImageBase(String newBaseAddress) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Image Base");
                try {
                    String oldBase = currentProgram.getImageBase().toString();
                    Address newBase = currentProgram.getAddressFactory().getAddress(newBaseAddress);
                    currentProgram.setImageBase(newBase, true);
                    result.put("success", true);
                    result.put("oldBase", oldBase);
                    result.put("newBase", newBaseAddress);
                } catch (Exception e) {
                    result.put("error", "Error setting image base: " + e.getMessage());
                    Msg.error(this, "Error setting image base: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.20 IoT Tools - createMemoryBlock ---

    public Map<String, Object> createMemoryBlock(String name, String addressStr, long size, String permissions, boolean isOverlay) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Create Memory Block");
                try {
                    long maxBlockSize = 256L * 1024 * 1024; // 256 MB
                    if (size > maxBlockSize) {
                        result.put("error", "Memory block size exceeds maximum of 256 MB");
                        return;
                    }
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    Memory memory = currentProgram.getMemory();
                    String perms = permissions != null ? permissions.toLowerCase() : "r";
                    MemoryBlock block;
                    if (isOverlay) {
                        block = memory.createInitializedBlock(name, addr, size, (byte) 0, TaskMonitor.DUMMY, true);
                    } else {
                        block = memory.createInitializedBlock(name, addr, size, (byte) 0, TaskMonitor.DUMMY, false);
                    }
                    block.setRead(perms.contains("r"));
                    block.setWrite(perms.contains("w"));
                    block.setExecute(perms.contains("x"));
                    result.put("success", true);
                    result.put("name", name);
                    result.put("start", block.getStart().toString());
                    result.put("end", block.getEnd().toString());
                    result.put("size", block.getSize());
                    result.put("permissions", (block.isRead() ? "r" : "-") + (block.isWrite() ? "w" : "-") + (block.isExecute() ? "x" : "-"));
                } catch (Exception e) {
                    result.put("error", "Error creating memory block: " + e.getMessage());
                    Msg.error(this, "Error creating memory block: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.21 IoT Tools - detectSecurityMitigations ---

    public Map<String, Object> detectSecurityMitigations() {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            List<Map<String, Object>> mitigations = new ArrayList<>();
            int score = 0;
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            FunctionManager functionManager = currentProgram.getFunctionManager();

            // 1. Stack canaries (__stack_chk_fail, __stack_chk_guard)
            boolean hasStackCanary = false;
            String[] canarySymbols = {"__stack_chk_fail", "__stack_chk_guard", "__security_check_cookie", "__security_cookie"};
            for (String canaryName : canarySymbols) {
                SymbolIterator syms = symbolTable.getSymbols(canaryName);
                if (syms.hasNext()) {
                    hasStackCanary = true;
                    break;
                }
            }
            Map<String, Object> canaryMit = new HashMap<>();
            canaryMit.put("name", "Stack Canaries");
            canaryMit.put("enabled", hasStackCanary);
            canaryMit.put("details", hasStackCanary ? "Stack protection symbols found" : "No stack canary symbols detected");
            mitigations.add(canaryMit);
            if (hasStackCanary) score += 20;

            // 2. NX (Non-executable stack)
            boolean hasNX = true;
            Memory memory = currentProgram.getMemory();
            for (MemoryBlock block : memory.getBlocks()) {
                String blockName = block.getName().toLowerCase();
                if (blockName.contains("stack") && block.isExecute()) {
                    hasNX = false;
                    break;
                }
            }
            Map<String, Object> nxMit = new HashMap<>();
            nxMit.put("name", "NX (Non-Executable Stack)");
            nxMit.put("enabled", hasNX);
            nxMit.put("details", hasNX ? "No executable stack segments detected" : "Executable stack segment found");
            mitigations.add(nxMit);
            if (hasNX) score += 20;

            // 3. ASLR (check for relocations / PIE)
            boolean hasASLR = false;
            ghidra.framework.options.Options progInfo = currentProgram.getOptions("Program Information");
            for (String optName : progInfo.getOptionNames()) {
                try {
                    String val = progInfo.getValueAsString(optName);
                    if (val != null) {
                        String lower = (optName + "=" + val).toLowerCase();
                        if (lower.contains("reloc") || lower.contains("pie") || lower.contains("aslr") ||
                            lower.contains("dynamic base") || lower.contains("dll characteristics")) {
                            if (lower.contains("true") || lower.contains("yes") || lower.contains("0x")) {
                                hasASLR = true;
                            }
                        }
                    }
                } catch (Exception e) { /* skip */ }
            }
            Map<String, Object> aslrMit = new HashMap<>();
            aslrMit.put("name", "ASLR / PIE");
            aslrMit.put("enabled", hasASLR);
            aslrMit.put("details", hasASLR ? "Relocation or PIE indicators found" : "No ASLR/PIE indicators detected");
            mitigations.add(aslrMit);
            if (hasASLR) score += 20;

            // 4. FORTIFY_SOURCE (fortified function variants)
            boolean hasFortify = false;
            String[] fortifyFuncs = {"__sprintf_chk", "__fprintf_chk", "__memcpy_chk", "__strcpy_chk", "__strcat_chk", "__snprintf_chk"};
            for (String fname : fortifyFuncs) {
                SymbolIterator syms = symbolTable.getSymbols(fname);
                if (syms.hasNext()) {
                    hasFortify = true;
                    break;
                }
            }
            Map<String, Object> fortifyMit = new HashMap<>();
            fortifyMit.put("name", "FORTIFY_SOURCE");
            fortifyMit.put("enabled", hasFortify);
            fortifyMit.put("details", hasFortify ? "Fortified function variants found" : "No FORTIFY_SOURCE indicators detected");
            mitigations.add(fortifyMit);
            if (hasFortify) score += 20;

            // 5. RELRO (read-only relocations) - check for .got.plt section
            boolean hasRELRO = false;
            for (MemoryBlock block : memory.getBlocks()) {
                String blockName = block.getName().toLowerCase();
                if (blockName.contains(".got") && !block.isWrite()) {
                    hasRELRO = true;
                    break;
                }
            }
            Map<String, Object> relroMit = new HashMap<>();
            relroMit.put("name", "RELRO");
            relroMit.put("enabled", hasRELRO);
            relroMit.put("details", hasRELRO ? "Read-only GOT detected" : "No RELRO indicators detected");
            mitigations.add(relroMit);
            if (hasRELRO) score += 20;

            result.put("mitigations", mitigations);
            result.put("score", score);
            String summary;
            if (score >= 80) summary = "Strong security posture";
            else if (score >= 60) summary = "Moderate security posture";
            else if (score >= 40) summary = "Weak security posture";
            else summary = "Minimal security mitigations detected";
            result.put("summary", summary);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error detecting security mitigations: " + e.getMessage());
        }
        return result;
    }

    // --- 2.22 IoT Tools - findFormatStringVulns ---

    public Map<String, Object> findFormatStringVulns() {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            List<Map<String, Object>> vulnerabilities = new ArrayList<>();
            String[] formatFuncs = {"printf", "sprintf", "fprintf", "snprintf", "vprintf",
                "vsprintf", "vfprintf", "vsnprintf", "syslog", "wprintf", "swprintf"};
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            FunctionManager functionManager = currentProgram.getFunctionManager();
            ReferenceManager refManager = currentProgram.getReferenceManager();

            for (String funcName : formatFuncs) {
                SymbolIterator symbols = symbolTable.getSymbols(funcName);
                while (symbols.hasNext()) {
                    Symbol symbol = symbols.next();
                    Iterator<Reference> refs = refManager.getReferencesTo(symbol.getAddress());
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        if (!ref.getReferenceType().isCall()) continue;
                        Address callAddr = ref.getFromAddress();
                        Function callerFunc = functionManager.getFunctionContaining(callAddr);
                        if (callerFunc == null) continue;

                        // Decompile and check if format string is a variable (not a literal)
                        String decompiled = decompileToC(callerFunc);
                        if (decompiled != null) {
                            // Simple heuristic: if the function call uses a variable as format arg
                            // Look for patterns like printf(var) vs printf("literal")
                            String confidence = "low";
                            // Check for the function name in decompiled code around the call
                            if (decompiled.contains(funcName + "(") &&
                                !decompiled.contains(funcName + "(\"")) {
                                confidence = "high";
                            } else if (decompiled.contains(funcName)) {
                                confidence = "medium";
                            }

                            Map<String, Object> vuln = new HashMap<>();
                            vuln.put("function", callerFunc.getName());
                            vuln.put("callAddress", callAddr.toString());
                            vuln.put("formatFunction", funcName);
                            vuln.put("confidence", confidence);
                            vulnerabilities.add(vuln);
                        }
                    }
                }
            }
            result.put("vulnerabilities", vulnerabilities);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error finding format string vulns: " + e.getMessage());
        }
        return result;
    }

    // --- 2.23 IoT Tools - findROPGadgets ---

    public Map<String, Object> findROPGadgets(int maxLength, String[] types) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            if (maxLength <= 0) maxLength = 5;
            if (maxLength > 20) maxLength = 20;
            Set<String> typeSet = new HashSet<>();
            if (types != null && types.length > 0) {
                for (String t : types) typeSet.add(t.toLowerCase());
            } else {
                typeSet.add("ret");
                typeSet.add("jmp");
                typeSet.add("call");
            }

            List<Map<String, Object>> gadgets = new ArrayList<>();
            Memory memory = currentProgram.getMemory();
            Listing listing = currentProgram.getListing();

            // Search for RET instructions (0xC3 for x86)
            if (typeSet.contains("ret")) {
                byte[] retByte = {(byte) 0xC3};
                Address searchAddr = memory.getMinAddress();
                int count = 0;
                while (searchAddr != null && count < 500) {
                    Address found = memory.findBytes(searchAddr, retByte, null, true, TaskMonitor.DUMMY);
                    if (found == null) break;
                    // Check if this is in an executable block
                    MemoryBlock block = memory.getBlock(found);
                    if (block != null && block.isExecute()) {
                        // Walk backwards to find gadget instructions
                        for (int back = 1; back <= maxLength; back++) {
                            try {
                                Address checkAddr = found.subtract(back);
                                Instruction instr = listing.getInstructionAt(checkAddr);
                                if (instr != null && instr.getAddress().add(instr.getLength()).equals(found) || back == 1) {
                                    // Build gadget from this point to RET
                                    List<String> tempInstrs = new ArrayList<>();
                                    Address walkAddr = checkAddr;
                                    boolean validGadget = true;
                                    while (walkAddr != null && walkAddr.compareTo(found) <= 0) {
                                        Instruction walkInstr = listing.getInstructionAt(walkAddr);
                                        if (walkInstr == null) {
                                            validGadget = false;
                                            break;
                                        }
                                        tempInstrs.add(walkInstr.toString());
                                        walkAddr = walkAddr.add(walkInstr.getLength());
                                    }
                                    if (validGadget && !tempInstrs.isEmpty() && tempInstrs.size() <= maxLength) {
                                        Map<String, Object> gadget = new HashMap<>();
                                        gadget.put("address", checkAddr.toString());
                                        gadget.put("instructions", tempInstrs);
                                        gadget.put("type", "ret");
                                        gadgets.add(gadget);
                                        count++;
                                    }
                                }
                            } catch (Exception e) {
                                // skip invalid address
                            }
                        }
                    }
                    try { searchAddr = found.add(1); } catch (Exception e) { break; }
                }
            }

            // Search for JMP reg patterns (0xFF 0xE0-0xE7 for x86)
            if (typeSet.contains("jmp")) {
                for (int reg = 0; reg <= 7; reg++) {
                    byte[] jmpReg = {(byte) 0xFF, (byte) (0xE0 + reg)};
                    Address searchAddr = memory.getMinAddress();
                    int count = 0;
                    while (searchAddr != null && count < 100) {
                        Address found = memory.findBytes(searchAddr, jmpReg, null, true, TaskMonitor.DUMMY);
                        if (found == null) break;
                        MemoryBlock block = memory.getBlock(found);
                        if (block != null && block.isExecute()) {
                            Instruction instr = listing.getInstructionAt(found);
                            if (instr != null) {
                                Map<String, Object> gadget = new HashMap<>();
                                gadget.put("address", found.toString());
                                List<String> instrs = new ArrayList<>();
                                instrs.add(instr.toString());
                                gadget.put("instructions", instrs);
                                gadget.put("type", "jmp");
                                gadgets.add(gadget);
                                count++;
                            }
                        }
                        try { searchAddr = found.add(2); } catch (Exception e) { break; }
                    }
                }
            }

            // Search for CALL reg patterns (0xFF 0xD0-0xD7 for x86)
            if (typeSet.contains("call")) {
                for (int reg = 0; reg <= 7; reg++) {
                    byte[] callReg = {(byte) 0xFF, (byte) (0xD0 + reg)};
                    Address searchAddr = memory.getMinAddress();
                    int count = 0;
                    while (searchAddr != null && count < 100) {
                        Address found = memory.findBytes(searchAddr, callReg, null, true, TaskMonitor.DUMMY);
                        if (found == null) break;
                        MemoryBlock block = memory.getBlock(found);
                        if (block != null && block.isExecute()) {
                            Instruction instr = listing.getInstructionAt(found);
                            if (instr != null) {
                                Map<String, Object> gadget = new HashMap<>();
                                gadget.put("address", found.toString());
                                List<String> instrs = new ArrayList<>();
                                instrs.add(instr.toString());
                                gadget.put("instructions", instrs);
                                gadget.put("type", "call");
                                gadgets.add(gadget);
                                count++;
                            }
                        }
                        try { searchAddr = found.add(2); } catch (Exception e) { break; }
                    }
                }
            }

            result.put("gadgets", gadgets);
            result.put("count", gadgets.size());
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error finding ROP gadgets: " + e.getMessage());
        }
        return result;
    }

    // --- 2.24 IoT Tools - setCallingConvention ---

    public Map<String, Object> setCallingConvention(String functionAddress, String convention) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Calling Convention");
                try {
                    Address entryAddr = currentProgram.getAddressFactory().getAddress(functionAddress);
                    FunctionManager functionManager = currentProgram.getFunctionManager();
                    Function function = functionManager.getFunctionAt(entryAddr);
                    if (function == null) {
                        result.put("error", "No function found at address " + functionAddress);
                        return;
                    }
                    String oldConvention = function.getCallingConventionName();
                    function.setCallingConvention(convention);
                    result.put("success", true);
                    result.put("function", function.getName());
                    result.put("oldConvention", oldConvention);
                    result.put("newConvention", convention);
                    // List available conventions
                    List<String> available = new ArrayList<>();
                    try {
                        for (PrototypeModel cc : currentProgram.getCompilerSpec().getCallingConventions()) {
                            available.add(cc.getName());
                        }
                    } catch (Exception e) { /* skip */ }
                    result.put("availableConventions", available);
                } catch (Exception e) {
                    result.put("error", "Error setting calling convention: " + e.getMessage());
                    Msg.error(this, "Error setting calling convention: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.25 IoT Tools - detectControlFlowFlattening ---

    public Map<String, Object> detectControlFlowFlattening(String functionAddress) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            Address entryAddr = currentProgram.getAddressFactory().getAddress(functionAddress);
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function function = functionManager.getFunctionAt(entryAddr);
            if (function == null) {
                result.put("error", "No function found at address " + functionAddress);
                return result;
            }
            BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
            CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(function.getBody(), TaskMonitor.DUMMY);
            List<CodeBlock> blocks = new ArrayList<>();
            while (blockIter.hasNext()) {
                blocks.add(blockIter.next());
            }
            int blockCount = blocks.size();
            // Analyze dispatcher pattern: look for a block with many outgoing edges
            String dispatcherAddress = null;
            int maxSuccessors = 0;
            int multiSuccessorBlocks = 0;
            for (CodeBlock block : blocks) {
                int successorCount = 0;
                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    destIter.next();
                    successorCount++;
                }
                if (successorCount > maxSuccessors) {
                    maxSuccessors = successorCount;
                    dispatcherAddress = block.getMinAddress().toString();
                }
                if (successorCount > 2) {
                    multiSuccessorBlocks++;
                }
            }
            // Also check for blocks that loop back to a common block (dispatcher)
            Map<String, Integer> incomingCount = new HashMap<>();
            for (CodeBlock block : blocks) {
                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    CodeBlockReference destRef = destIter.next();
                    String destAddr = destRef.getDestinationAddress().toString();
                    incomingCount.put(destAddr, incomingCount.getOrDefault(destAddr, 0) + 1);
                }
            }
            int maxIncoming = 0;
            String maxIncomingAddr = null;
            for (Map.Entry<String, Integer> entry : incomingCount.entrySet()) {
                if (entry.getValue() > maxIncoming) {
                    maxIncoming = entry.getValue();
                    maxIncomingAddr = entry.getKey();
                }
            }

            // Heuristics for CFF detection
            boolean isFlattened = false;
            String confidence = "low";
            // A function is likely flattened if:
            // 1. It has many blocks
            // 2. One block has many successors (dispatcher/switch)
            // 3. Many blocks converge back to a single block
            if (blockCount > 10 && maxSuccessors > 4 && maxIncoming > blockCount / 3) {
                isFlattened = true;
                confidence = "high";
            } else if (blockCount > 8 && (maxSuccessors > 3 || maxIncoming > blockCount / 4)) {
                isFlattened = true;
                confidence = "medium";
            } else if (blockCount > 5 && maxSuccessors > 2 && multiSuccessorBlocks > 0) {
                confidence = "low";
                // Might be a normal switch, not necessarily flattened
            }

            result.put("isFlattened", isFlattened);
            result.put("confidence", confidence);
            result.put("dispatcherAddress", dispatcherAddress);
            result.put("blockCount", blockCount);
            result.put("maxSuccessors", maxSuccessors);
            result.put("maxIncomingEdges", maxIncoming);
            if (maxIncomingAddr != null) {
                result.put("convergenceBlock", maxIncomingAddr);
            }
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error detecting CFF: " + e.getMessage());
        }
        return result;
    }

    // --- 2.26 IoT Tools - setMemoryPermissions ---

    public Map<String, Object> setMemoryPermissions(String addressStr, boolean read, boolean write, boolean execute, boolean isVolatile) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Set Memory Permissions");
                try {
                    Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                    Memory memory = currentProgram.getMemory();
                    MemoryBlock block = memory.getBlock(addr);
                    if (block == null) {
                        result.put("error", "No memory block at address " + addressStr);
                        return;
                    }
                    block.setRead(read);
                    block.setWrite(write);
                    block.setExecute(execute);
                    block.setVolatile(isVolatile);
                    result.put("success", true);
                    result.put("blockName", block.getName());
                    result.put("permissions",
                        (read ? "r" : "-") + (write ? "w" : "-") + (execute ? "x" : "-") + (isVolatile ? "v" : ""));
                } catch (Exception e) {
                    result.put("error", "Error setting memory permissions: " + e.getMessage());
                    Msg.error(this, "Error setting memory permissions: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.27 IoT Tools - markCodeCoverage ---

    public Map<String, Object> markCodeCoverage(List<String> addresses, String bookmarkType) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        if (bookmarkType == null || bookmarkType.trim().isEmpty()) {
            bookmarkType = "Analysis";
        }
        final String bmType = bookmarkType;
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = currentProgram.startTransaction("Mark Code Coverage");
                try {
                    BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
                    int marked = 0;
                    for (String addrStr : addresses) {
                        try {
                            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
                            bookmarkManager.setBookmark(addr, bmType, "Coverage", "Covered");
                            marked++;
                        } catch (Exception e) {
                            Msg.error(this, "Error marking address " + addrStr + ": " + e.getMessage());
                        }
                    }
                    result.put("success", true);
                    result.put("markedCount", marked);
                } catch (Exception e) {
                    result.put("error", "Error marking coverage: " + e.getMessage());
                    Msg.error(this, "Error marking coverage: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(txId, Boolean.TRUE.equals(result.get("success")));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.put("error", "Error executing on Swing thread: " + e.getMessage());
            Msg.error(this, "Error executing on Swing thread: " + e.getMessage());
        }
        return result;
    }

    // --- 2.28 Emulation ---

    public Map<String, Object> emulateFunction(String addressStr, List<Long> args, int maxSteps) {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            Address entryAddr = currentProgram.getAddressFactory().getAddress(addressStr);
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function function = functionManager.getFunctionAt(entryAddr);
            if (function == null) {
                result.put("error", "No function found at address " + addressStr);
                return result;
            }

            ghidra.app.emulator.EmulatorHelper emu = new ghidra.app.emulator.EmulatorHelper(currentProgram);
            try {
                // Set up a return address that we can detect
                long fakeReturnAddr = 0xDEADBEEFL;
                String processor = currentProgram.getLanguage().getProcessor().toString().toLowerCase();
                boolean isX86 = processor.contains("x86") || processor.contains("386") || processor.contains("amd64");
                boolean isARM = processor.contains("arm") || processor.contains("aarch");

                if (isX86) {
                    // Push return address onto stack for x86
                    long sp = emu.readRegister("ESP").longValue();
                    sp -= currentProgram.getDefaultPointerSize();
                    emu.writeRegister("ESP", sp);
                    emu.writeMemoryValue(currentProgram.getAddressFactory().getAddress(Long.toHexString(sp)),
                        currentProgram.getDefaultPointerSize(), fakeReturnAddr);
                    // Set arguments - cdecl convention: push right to left on stack
                    if (args != null) {
                        for (int i = 0; i < args.size(); i++) {
                            long argAddr = sp + (long)(i + 1) * currentProgram.getDefaultPointerSize();
                            emu.writeMemoryValue(
                                currentProgram.getAddressFactory().getAddress(Long.toHexString(argAddr)),
                                currentProgram.getDefaultPointerSize(), args.get(i));
                        }
                    }
                } else if (isARM) {
                    // ARM: set LR to fake return, args in R0-R3
                    emu.writeRegister("lr", fakeReturnAddr);
                    String[] armRegs = {"r0", "r1", "r2", "r3"};
                    if (args != null) {
                        for (int i = 0; i < Math.min(args.size(), armRegs.length); i++) {
                            emu.writeRegister(armRegs[i], args.get(i));
                        }
                    }
                }

                emu.setBreakpoint(currentProgram.getAddressFactory().getAddress(Long.toHexString(fakeReturnAddr)));

                // Run emulation
                if (maxSteps <= 0) maxSteps = 10000;
                int stepsExecuted = 0;
                boolean hitBreakpoint = false;
                emu.writeRegister(emu.getPCRegister(), entryAddr.getOffset());
                while (stepsExecuted < maxSteps) {
                    boolean ok = emu.step(TaskMonitor.DUMMY);
                    stepsExecuted++;
                    if (!ok) break;
                    long pc = emu.readRegister(emu.getPCRegister()).longValue();
                    if (pc == fakeReturnAddr) {
                        hitBreakpoint = true;
                        break;
                    }
                }

                // Read return value
                long returnValue = 0;
                if (isX86) {
                    returnValue = emu.readRegister("EAX").longValue();
                } else if (isARM) {
                    returnValue = emu.readRegister("r0").longValue();
                }

                // Collect register state
                Map<String, Long> registersAfter = new HashMap<>();
                if (isX86) {
                    String[] regs = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP"};
                    for (String reg : regs) {
                        try {
                            registersAfter.put(reg, emu.readRegister(reg).longValue());
                        } catch (Exception e) { /* skip */ }
                    }
                } else if (isARM) {
                    for (int i = 0; i <= 12; i++) {
                        try {
                            registersAfter.put("r" + i, emu.readRegister("r" + i).longValue());
                        } catch (Exception e) { /* skip */ }
                    }
                }

                result.put("returnValue", returnValue);
                result.put("registersAfter", registersAfter);
                result.put("stepsExecuted", stepsExecuted);
                result.put("completed", hitBreakpoint);
            } finally {
                emu.dispose();
            }
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error emulating function: " + e.getMessage());
        }
        return result;
    }

    // --- 2.29 Dynamic API Resolution ---

    public Map<String, Object> findDynamicAPIResolution() {
        Map<String, Object> result = new HashMap<>();
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }
        try {
            List<Map<String, Object>> dynamicImports = new ArrayList<>();
            String[] resolverAPIs = {"GetProcAddress", "dlsym", "dlopen", "LoadLibrary",
                "LoadLibraryA", "LoadLibraryW", "LoadLibraryEx", "LoadLibraryExA", "LoadLibraryExW",
                "GetModuleHandle", "GetModuleHandleA", "GetModuleHandleW"};
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            FunctionManager functionManager = currentProgram.getFunctionManager();
            ReferenceManager refManager = currentProgram.getReferenceManager();

            for (String apiName : resolverAPIs) {
                SymbolIterator symbols = symbolTable.getSymbols(apiName);
                while (symbols.hasNext()) {
                    Symbol symbol = symbols.next();
                    Iterator<Reference> refs = refManager.getReferencesTo(symbol.getAddress());
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        if (!ref.getReferenceType().isCall()) continue;
                        Address callAddr = ref.getFromAddress();
                        Function callerFunc = functionManager.getFunctionContaining(callAddr);

                        Map<String, Object> dynImport = new HashMap<>();
                        dynImport.put("callSite", callAddr.toString());
                        dynImport.put("resolverAPI", apiName);
                        if (callerFunc != null) {
                            dynImport.put("callerFunction", callerFunc.getName());
                            // Try to extract the resolved function name from decompiled code
                            String decompiled = decompileToC(callerFunc);
                            if (decompiled != null) {
                                // Look for string literals near the call that might be function names
                                // Pattern: GetProcAddress(..., "FunctionName") or dlsym(..., "func_name")
                                Pattern strPattern = Pattern.compile(
                                    apiName + "\\s*\\([^)]*\"([^\"]+)\"[^)]*\\)");
                                Matcher matcher = strPattern.matcher(decompiled);
                                List<String> resolvedNames = new ArrayList<>();
                                while (matcher.find()) {
                                    resolvedNames.add(matcher.group(1));
                                }
                                if (!resolvedNames.isEmpty()) {
                                    dynImport.put("resolvedNames", resolvedNames);
                                }
                            }
                        }
                        dynamicImports.add(dynImport);
                    }
                }
            }
            result.put("dynamicImports", dynamicImports);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            Msg.error(this, "Error finding dynamic API resolution: " + e.getMessage());
        }
        return result;
    }

    // ==================== ASYNC DECOMPILATION ====================

    /** Auto-cleanup delay for completed async tasks (10 minutes). */
    private static final long ASYNC_TASK_TTL_MS = 10 * 60 * 1000L;

    /**
     * Start an asynchronous decompilation of a function at the given address.
     * Returns immediately with a task ID that can be polled via getDecompileResult().
     */
    public Map<String, Object> decompileFunctionAsync(String addressStr) {
        Map<String, Object> result = new HashMap<>();
        if (asyncTasks.size() >= MAX_ASYNC_TASKS) {
            result.put("error", "Too many pending async tasks (max " + MAX_ASYNC_TASKS + "). Wait for existing tasks to complete.");
            return result;
        }
        if (currentProgram == null) {
            result.put("error", "No program loaded");
            return result;
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            result.put("error", "Invalid address: " + addressStr);
            return result;
        }

        Function function = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (function == null) {
            function = currentProgram.getFunctionManager().getFunctionContaining(addr);
        }
        if (function == null) {
            result.put("error", "No function found at address: " + addressStr);
            return result;
        }

        String taskId = UUID.randomUUID().toString();
        String functionName = function.getName();
        String functionAddr = function.getEntryPoint().toString();

        // Capture the function reference for the async task
        final Function asyncFunction = function;
        // Capture current program reference at submission time
        final Program programSnapshot = currentProgram;

        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(programSnapshot);
                DecompileResults results = decomp.decompileFunction(
                    asyncFunction, DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
                if (results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC();
                    return code != null ? code : "Decompilation returned null";
                }
                return "Decompilation did not complete successfully";
            } finally {
                decomp.dispose();
            }
        }, decompilerPool);

        asyncTasks.put(taskId, future);

        // Schedule auto-cleanup after TTL (uses dedicated scheduler instead of blocking a pool thread)
        cleanupScheduler.schedule(() -> asyncTasks.remove(taskId), 10, TimeUnit.MINUTES);

        result.put("taskId", taskId);
        result.put("status", "submitted");
        result.put("functionName", functionName);
        result.put("address", functionAddr);
        return result;
    }

    /**
     * Poll for the result of an async decompilation task.
     */
    public Map<String, Object> getDecompileResult(String taskId) {
        Map<String, Object> result = new HashMap<>();

        CompletableFuture<String> future = asyncTasks.get(taskId);
        if (future == null) {
            result.put("status", "not_found");
            result.put("error", "No task found with ID: " + taskId + " (may have expired after 10 minutes)");
            return result;
        }

        if (!future.isDone()) {
            result.put("status", "pending");
            result.put("taskId", taskId);
            return result;
        }

        try {
            String code = future.get(); // non-blocking since isDone() is true
            result.put("status", "completed");
            result.put("taskId", taskId);
            result.put("result", code);
            asyncTasks.remove(taskId); // Clean up after retrieval
        } catch (Exception e) {
            result.put("status", "error");
            result.put("taskId", taskId);
            result.put("error", e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
            asyncTasks.remove(taskId); // Clean up on error too
        }

        return result;
    }

    /**
     * Shut down the async decompiler pool and clear pending tasks.
     * Called by MCPServer.stopServer() during plugin shutdown.
     */
    public void shutdown() {
        asyncTasks.clear();
        decompilerPool.shutdownNow();
        try {
            if (!decompilerPool.awaitTermination(5, TimeUnit.SECONDS)) {
                Msg.warn(this, "Decompiler pool did not terminate within 5 seconds");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

}