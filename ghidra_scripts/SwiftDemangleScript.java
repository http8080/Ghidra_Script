/*
 * SwiftDemangleScript.java
 *
 * A Ghidra Java Script for ultra-fast Swift symbol demangling with caching
 * Minimizes console overhead and avoids duplicate demangle calls
 * Place in your Ghidra scripts directory (e.g. ~/ghidra_scripts)
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

public class SwiftDemangleScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = currentProgram;
        List<Function> funcs = toList(program.getFunctionManager().getFunctions(true));
        List<Symbol> labels = new ArrayList<>();
        for (Symbol sym : program.getSymbolTable().getAllSymbols(true)) {
            if (sym.getSymbolType() == SymbolType.LABEL) {
                labels.add(sym);
            }
        }

        int totalSymbols = funcs.size() + labels.size();
        monitor.initialize(totalSymbols);

        println("Collecting symbol names...");
        List<String> allNames = new ArrayList<>(totalSymbols);
        for (Function f : funcs) {
            allNames.add(f.getName());
        }
        for (Symbol s : labels) {
            allNames.add(s.getName());
        }

        println("Preparing unique demangle list...");
        Set<String> uniqueNames = new LinkedHashSet<>(allNames);

        println("Demangling " + uniqueNames.size() + " unique symbols...");
        Map<String, String> demangleMap = batchDemangleUnique(uniqueNames);

        int renamedCount = 0;
        int idx = 0;
        // Apply to functions
        for (Function f : funcs) {
            monitor.checkCanceled();
            String orig = allNames.get(idx);
            String dem = demangleMap.get(orig);
            String clean = cleanName(dem);
            if (!clean.equals(orig)) {
                f.setComment("Original: " + orig + "\nDemangled: " + dem);
                f.setName(clean, SourceType.USER_DEFINED);
                renamedCount++;
            }
            idx++;
            monitor.incrementProgress(1);
        }
        // Apply to labels
        for (Symbol s : labels) {
            monitor.checkCanceled();
            String orig = allNames.get(idx);
            String dem = demangleMap.get(orig);
            String clean = cleanName(dem);
            if (!clean.equals(orig)) {
                program.getListing().setComment(s.getAddress(), CodeUnit.EOL_COMMENT,
                    "Original: " + orig + "\nDemangled: " + dem);
                s.setName(clean, SourceType.USER_DEFINED);
                renamedCount++;
            }
            idx++;
            monitor.incrementProgress(1);
        }

        println("Done. Renamed " + renamedCount + " symbols out of " + totalSymbols + ".");
    }

    /**
     * Demangles a set of unique names and returns a mapping of original to demangled.
     */
    private Map<String, String> batchDemangleUnique(Set<String> names) throws IOException, InterruptedException {
        List<String> nameList = new ArrayList<>(names);
        List<String> demangledList = demangleProcess(nameList);
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < nameList.size(); i++) {
            map.put(nameList.get(i), demangledList.get(i));
        }
        return map;
    }

    /**
     * Internal: invokes swift-demangle once for a list of names.
     */
    private List<String> demangleProcess(List<String> names) throws IOException, InterruptedException {
        String osName = System.getProperty("os.name").toLowerCase();
        ProcessBuilder pb = osName.contains("mac")
            ? new ProcessBuilder("xcrun", "swift-demangle", "--simplified", "--compact")
            : new ProcessBuilder("swift-demangle", "--simplified", "--compact");
        pb.redirectErrorStream(true);
        Process process = pb.start();

        try (OutputStream out = process.getOutputStream();
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
             BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            for (String name : names) {
                writer.write(name);
                writer.newLine();
            }
            writer.flush();
            out.close();

            List<String> results = new ArrayList<>(names.size());
            String line;
            while ((line = reader.readLine()) != null) {
                results.add(line.trim());
            }
            process.waitFor();
            return results;
        }
    }

    /**
     * Cleans demangled name by stripping params and replacing invalid characters.
     */
    private String cleanName(String input) {
        String base = input.split("\\(")[0];
        return base.replace(" ", "_")
                   .replace("<", "_")
                   .replace(">", "_");
    }

    /** Utility to convert Iterable to List. */
    private <T> List<T> toList(Iterable<T> iterable) {
        List<T> list = new ArrayList<>();
        for (T item : iterable) {
            list.add(item);
        }
        return list;
    }
}
