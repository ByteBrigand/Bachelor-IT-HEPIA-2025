//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.Options;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class DecompileScript extends GhidraScript {

    private static final Set<String> IGNORED_NAMES = new HashSet<>(Arrays.asList(
        "_start", "__libc_csu_fini", "__libc_csu_init", "__libc_start_main",
        "__data_start", "__dso_handle", "_IO_stdin_used", "frame_dummy",
        "call_frame_dummy", "__do_global_dtors", "__do_global_dtors_aux",
        "call___do_global_dtors_aux", "__do_global_ctors", "__do_global_ctors_1",
        "__do_global_ctors_aux", "call___do_global_ctors_aux", "__gmon_start__",
        "_init_proc", ".init_proc", "_term_proc", ".term_proc", "__uClibc_main",
        "abort", "exit", "_Exit", "panic", "terminate", "_init", "_fini",
        "register_tm_clones", "deregister_tm_clones", "__sinit"
    ));

    @Override
    protected void run() throws Exception {
        println("===[ Ghidra Headless C Decompiler Sorted ]===");

        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: <output_file> [all|single:<functionname>]");
            return;
        }
        String outputFile = args[0];
        String mode = (args.length > 1) ? args[1].trim().toLowerCase() : "all";
        String singleFunctionName = null;
        if (mode.startsWith("single:")) {
            singleFunctionName = mode.substring("single:".length());
            mode = "single";
        }

        runAutoAnalysis();

        // Decompiler options (use Ghidra's preferred way)
        DecompileOptions options = new DecompileOptions();
        DecompInterface decomp = new DecompInterface();
        decomp.setOptions(options);
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.toggleJumpLoads(true);
        decomp.toggleParamMeasures(false);
        decomp.setSimplificationStyle("decompile");
        if (!decomp.openProgram(currentProgram)) {
            throw new IOException("Decompiler error: " + decomp.getLastMessage());
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        // Sorted list of functions (by entry address, unique only)
        List<Function> allFuncs = getFunctionsSorted(fm, mode, singleFunctionName);
        Set<Address> seen = new HashSet<>();
        List<Function> funcs = new ArrayList<>();
        for (Function f : allFuncs) {
            if (seen.add(f.getEntryPoint())) {
                funcs.add(f);
            }
        }

        // Prepare output file/directory
        Path outPath = Paths.get(outputFile);
        Files.createDirectories(outPath.getParent() != null ? outPath.getParent() : Paths.get("."));

        PrintWriter writer = new PrintWriter(Files.newBufferedWriter(outPath));
        try {
            // Write header
            writer.println("// Decompiled by Ghidra DecompileScript");
            writer.println("// Original: " + currentProgram.getName());
            writer.println("// Date: " + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            writer.println("// Architecture: " + currentProgram.getLanguage().getProcessor());
            writer.println();

            // Extern declarations
            Set<String> externSigs = new HashSet<>();
            writer.println("// External function declarations");
            for (Function ext : fm.getExternalFunctions()) {
                String sig = ext.getSignature().getPrototypeString();
                if (!sig.contains("undefined") && externSigs.add(sig)) {
                    writer.println("extern " + sig + ";");
                }
            }
            writer.println();

            // Forward declarations
            Set<String> forwardSigs = new HashSet<>();
            writer.println("// Forward declarations");
            for (Function f : funcs) {
                if (!f.isExternal() && !isPLTFunction(f) && !forwardSigs.contains(f.getSignature().getPrototypeString())) {
                    String sig = f.getSignature().getPrototypeString();
                    if (!sig.contains("undefined")) {
                        writer.println(sig + ";");
                        forwardSigs.add(sig);
                    }
                }
            }
            writer.println("// Function implementations");

            int successCount = 0, failCount = 0;
            for (Function f : funcs) {
                monitor.checkCanceled();
                String fname = f.getName();
                if (IGNORED_NAMES.contains(fname) || isPLTFunction(f) || f.isExternal()) continue;
                println("Decompiling: " + fname);
                try {
                    DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                    if (res == null || res.getDecompiledFunction() == null) {
                        println("Failed: " + fname + " (no decompiled result)");
                        failCount++;
                        continue;
                    }
                    String ccode = res.getDecompiledFunction().getC();
                    if (ccode == null || ccode.trim().isEmpty()) {
                        println("Failed: " + fname + " (empty code)");
                        failCount++;
                        continue;
                    }
                    writer.println();
                    writer.println("/* " + "=".repeat(50) + " */");
                    writer.println("// Function: " + fname);
                    writer.println("// Address: " + f.getEntryPoint());
                    writer.println("// Signature: " + f.getSignature());
                    writer.println(ccode);
                    successCount++;
                } catch (Exception ex) {
                    StringWriter sw = new StringWriter();
                    ex.printStackTrace(new PrintWriter(sw));
                    println("Error decompiling " + fname + ": " + sw.toString());
                    failCount++;
                }
            }
            writer.flush();
            println("===[ Done ]===");
            println("Successfully decompiled: " + successCount + " function(s)");
            println("Failed: " + failCount + " function(s)");
            println("Output: " + outPath.toAbsolutePath());
        } finally {
            writer.close();
            decomp.dispose();
        }
    }

    private List<Function> getFunctionsSorted(FunctionManager fm, String mode, String singleFunctionName) {
        List<Function> funcs = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if ("single".equals(mode)) {
                if (f.getName().equals(singleFunctionName)) {
                    funcs.add(f);
                    break;
                }
            } else {
                funcs.add(f);
            }
        }
        // Sort by entry address for deterministic output
        funcs.sort(Comparator.comparing(Function::getEntryPoint));
        return funcs;
    }

    private boolean isPLTFunction(Function function) {
        try {
            Memory memory = currentProgram.getMemory();
            MemoryBlock block = memory.getBlock(function.getEntryPoint());
            if (block != null) {
                String blockName = block.getName().toLowerCase();
                if (blockName.contains(".plt") || blockName.contains("procedure.linkage") || blockName.contains("@plt")) {
                    return true;
                }
            }
            String name = function.getName().toLowerCase();
            if (name.contains(".plt") || name.contains("@plt")) return true;
            if (function.isThunk() && function.getThunkedFunction(true).isExternal()) return true;
        } catch (Exception e) {
            println("Warning: Error checking PLT for " + function.getName() + ": " + e.getMessage());
        }
        return false;
    }

    private void runAutoAnalysis() throws Exception {
        Program program = getCurrentProgram();
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        options.setBoolean("Aggressive Instruction Finder", true);
        options.setBoolean("Decompiler Parameter ID", true);
        mgr.startAnalysis(monitor);
        mgr.waitForAnalysis(null, monitor);
    }
}

