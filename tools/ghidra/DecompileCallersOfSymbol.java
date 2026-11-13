// SPDX-License-Identifier: MIT
// Decompiles every function that calls the named symbol(s), so the call
// arguments are visible. Args: <output.c> <symbol> [<symbol> ...]
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import java.io.File;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompileCallersOfSymbol extends GhidraScript {
  @Override protected void run() throws Exception {
    String[] a = getScriptArgs();
    DecompInterface dec = new DecompInterface(); dec.openProgram(currentProgram);
    try (PrintWriter out = new PrintWriter(new File(a[0]), "UTF-8")) {
      for (int i = 1; i < a.length; i++) {
        String name = a[i];
        Set<Function> callers = new LinkedHashSet<>();
        for (Symbol sym : currentProgram.getSymbolTable().getSymbols(name)) {
          out.printf("/* symbol %s @ %s (%s) */%n", name, sym.getAddress(), sym.getSymbolType());
          for (Reference r : getReferencesTo(sym.getAddress())) {
            Function f = getFunctionContaining(r.getFromAddress());
            if (f != null) callers.add(f);
          }
          // also follow thunks: functions that are thunks to this
        }
        if (callers.isEmpty()) out.printf("/* no callers found for %s */%n", name);
        for (Function f : callers) {
          out.printf("%n/* ===== caller of %s: %s @ %s ===== */%n", name, f.getName(), f.getEntryPoint());
          DecompileResults res = dec.decompileFunction(f, 90, monitor);
          out.println(res.decompileCompleted() ? res.getDecompiledFunction().getC() : "/* decompile failed */");
        }
      }
    } finally { dec.dispose(); }
    println("done");
  }
}
