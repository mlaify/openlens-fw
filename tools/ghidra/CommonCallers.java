// SPDX-License-Identifier: MIT
// Walks the call graph upward from several target functions and reports the functions that
// (transitively, within N levels) reach the most targets, nearest first. Finds the routine that
// drives a sequence of calls (e.g. a media pipeline init) in a stripped binary.
// Args: <output.txt> <maxDepth> <addr> [<addr> ...]
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.PrintWriter;
import java.util.*;

public class CommonCallers extends GhidraScript {
  @Override protected void run() throws Exception {
    String[] a = getScriptArgs();
    int maxDepth = Integer.parseInt(a[1]);
    Map<Function, Set<String>> reach = new HashMap<>();
    Map<Function, Integer> depthOf = new HashMap<>();
    for (int i = 2; i < a.length; i++) {
      Function t = getFunctionAt(toAddr(a[i]));
      if (t == null) { println("no function at " + a[i]); continue; }
      Deque<Function> q = new ArrayDeque<>(); Map<Function, Integer> d = new HashMap<>();
      q.add(t); d.put(t, 0);
      while (!q.isEmpty()) {
        Function f = q.poll(); int k = d.get(f);
        reach.computeIfAbsent(f, x -> new TreeSet<>()).add(a[i]);
        depthOf.merge(f, k, Math::max);
        if (k >= maxDepth) continue;
        for (Function c : f.getCallingFunctions(monitor)) if (!d.containsKey(c)) { d.put(c, k + 1); q.add(c); }
      }
    }
    List<Function> fs = new ArrayList<>(reach.keySet());
    fs.sort((x, y) -> reach.get(y).size() != reach.get(x).size()
        ? reach.get(y).size() - reach.get(x).size() : depthOf.get(x) - depthOf.get(y));
    try (PrintWriter out = new PrintWriter(new File(a[0]), "UTF-8")) {
      for (Function f : fs.subList(0, Math.min(40, fs.size())))
        out.printf("%s\t%s\treaches=%d\tdepth=%d\t%s%n", f.getEntryPoint(), f.getName(),
                   reach.get(f).size(), depthOf.get(f), reach.get(f));
    }
    println("Wrote " + a[0]);
  }
}
