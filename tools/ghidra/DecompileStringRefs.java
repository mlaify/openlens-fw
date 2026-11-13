// SPDX-License-Identifier: MIT
// Decompiles every function that references a string containing any of the
// given substrings. Args: <output.c> <substring> [<substring> ...]
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import java.io.File;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class DecompileStringRefs extends GhidraScript {
  @Override protected void run() throws Exception {
    String[] args = getScriptArgs();
    Map<Function, Set<String>> hits = new LinkedHashMap<>();
    for (int i = 1; i < args.length; i++) {
      for (Function f : functionsReferencing(args[i])) {
        hits.computeIfAbsent(f, k -> new LinkedHashSet<>()).add(args[i]);
      }
    }
    DecompInterface dec = new DecompInterface();
    dec.openProgram(currentProgram);
    try (PrintWriter out = new PrintWriter(new File(args[0]), "UTF-8")) {
      out.printf("/* %s: %d functions */%n", currentProgram.getName(), hits.size());
      for (Map.Entry<Function, Set<String>> e : hits.entrySet()) {
        out.printf("%n/* ===== %s @ %s <- %s */%n", e.getKey().getName(), e.getKey().getEntryPoint(), e.getValue());
        DecompileResults r = dec.decompileFunction(e.getKey(), 120, monitor);
        out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "/* " + r.getErrorMessage() + " */");
      }
    } finally { dec.dispose(); }
    println("Wrote " + args[0] + " (" + hits.size() + " functions)");
  }

  // ARM code reaches strings through literal pools, so a data reference is
  // followed one hop back to the code that loads it.
  private Set<Function> functionsReferencing(String target) throws Exception {
    Set<Function> found = new LinkedHashSet<>();
    Memory mem = currentProgram.getMemory();
    byte[] pattern = target.getBytes("US-ASCII");
    Address a = mem.findBytes(mem.getMinAddress(), pattern, null, true, monitor);
    while (a != null && !monitor.isCancelled()) {
      for (Reference r : getReferencesTo(stringStart(a))) {
        Function f = getFunctionContaining(r.getFromAddress());
        if (f != null) { found.add(f); continue; }
        for (Reference r2 : getReferencesTo(r.getFromAddress())) {
          Function f2 = getFunctionContaining(r2.getFromAddress());
          if (f2 != null) found.add(f2);
        }
      }
      Address next = a.next();
      a = next == null ? null : mem.findBytes(next, pattern, null, true, monitor);
    }
    return found;
  }

  private Address stringStart(Address a) throws Exception {
    Data d = getDataContaining(a);
    if (d != null) return d.getAddress();
    Address cur = a;
    for (int i = 0; i < 512; i++) {
      Address prev = cur.previous();
      if (prev == null || getByte(prev) == 0) break;
      cur = prev;
    }
    return cur;
  }
}
