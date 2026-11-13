// SPDX-License-Identifier: MIT
// Decompiles every function whose name matches one of the given names (exact match,
// external thunks skipped). Useful for shared libraries where the Ghidra image base
// differs from the ELF symbol value. Args: <output.c> <name> [<name> ...]
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class DecompileByName extends GhidraScript {
  @Override protected void run() throws Exception {
    String[] args = getScriptArgs();
    Set<String> want = new HashSet<>(Arrays.asList(args).subList(1, args.length));
    DecompInterface dec = new DecompInterface();
    dec.openProgram(currentProgram);
    int n = 0;
    try (PrintWriter out = new PrintWriter(new File(args[0]), "UTF-8")) {
      for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        if (f.isThunk() || f.isExternal() || !want.contains(f.getName())) continue;
        DecompileResults r = dec.decompileFunction(f, 120, monitor);
        out.println("/* ===== " + f.getName() + " @ " + f.getEntryPoint() + " ===== */");
        out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "/* decompile failed: " + r.getErrorMessage() + " */");
        n++;
      }
    }
    println("Wrote " + args[0] + " (" + n + " functions)");
  }
}
