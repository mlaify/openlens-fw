// SPDX-License-Identifier: MIT
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.File;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class TraceFunction extends GhidraScript {
  @Override protected void run() throws Exception {
    String[] args = getScriptArgs();
    Address target = toAddr(args[0]);
    Function function = getFunctionAt(target);
    if (function == null) throw new IllegalArgumentException("No function at " + target);
    Set<Function> callers = new LinkedHashSet<>();
    for (Reference ref : getReferencesTo(target)) {
      Function caller = getFunctionContaining(ref.getFromAddress());
      if (caller != null) callers.add(caller);
    }
    DecompInterface dec = new DecompInterface();
    dec.openProgram(currentProgram);
    try (PrintWriter out = new PrintWriter(new File(args[1]), "UTF-8")) {
      out.printf("Target %s @ %s; callers %d%n", function.getName(), target, callers.size());
      DecompileResults targetResult = dec.decompileFunction(function, 120, monitor);
      out.println(targetResult.decompileCompleted() ? targetResult.getDecompiledFunction().getC() : targetResult.getErrorMessage());
      for (Function caller : callers) {
        out.printf("\n=== %s @ %s ===%n", caller.getName(), caller.getEntryPoint());
        DecompileResults result = dec.decompileFunction(caller, 120, monitor);
        out.println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : result.getErrorMessage());
      }
    } finally { dec.dispose(); }
  }
}
