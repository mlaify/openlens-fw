// SPDX-License-Identifier: MIT
// Pre-script for raw (non-ELF) ARM images such as a decompressed kernel Image: turns on the
// aggressive instruction finder so auto-analysis discovers functions without a symbol table.
// Use with: -preScript EnableAggressiveArm.java   (no args)
//@category Analysis
import ghidra.app.script.GhidraScript;
import java.util.Map;

public class EnableAggressiveArm extends GhidraScript {
  @Override protected void run() throws Exception {
    Map<String, String> opts = getCurrentAnalysisOptionsAndValues(currentProgram);
    for (String name : opts.keySet()) {
      if (name.contains("Aggressive Instruction Finder")) {
        setAnalysisOption(currentProgram, name, "true");
        println("enabled: " + name);
      }
    }
  }
}
