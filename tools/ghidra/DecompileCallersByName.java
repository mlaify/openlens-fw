// SPDX-License-Identifier: MIT
// Decompiles every function that calls a function whose name matches (handles
// PLT thunks via getCalledFunctions). Args: <output.c> <name> [<name> ...]
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.HashSet;

public class DecompileCallersByName extends GhidraScript {
  @Override protected void run() throws Exception {
    String[] a = getScriptArgs();
    Set<String> targets = new HashSet<>();
    for (int i = 1; i < a.length; i++) targets.add(a[i]);
    Set<Function> callers = new LinkedHashSet<>();
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
      for (Function c : f.getCalledFunctions(monitor)) {
        String n = c.getName();
        if (c.isThunk() && c.getThunkedFunction(true) != null) n = c.getThunkedFunction(true).getName();
        if (targets.contains(c.getName()) || targets.contains(n)) { callers.add(f); break; }
      }
    }
    DecompInterface dec = new DecompInterface(); dec.openProgram(currentProgram);
    try (PrintWriter out = new PrintWriter(new File(a[0]), "UTF-8")) {
      out.printf("/* %s: %d callers of %s */%n", currentProgram.getName(), callers.size(), String.join(",", targets));
      for (Function f : callers) {
        out.printf("%n/* ===== %s @ %s ===== */%n", f.getName(), f.getEntryPoint());
        DecompileResults r = dec.decompileFunction(f, 60, monitor);
        out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "/* decompile failed */");
      }
    } finally { dec.dispose(); }
    println("callers="+callers.size());
  }
}
