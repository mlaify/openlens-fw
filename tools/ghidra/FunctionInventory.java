// SPDX-License-Identifier: MIT
// Prints load metadata and the largest functions, plus functions whose names or
// nearby strings suggest auth/reset/update/cloud. Args: <output.txt>
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class FunctionInventory extends GhidraScript {
  @Override protected void run() throws Exception {
    String[] a = getScriptArgs();
    File out = new File(a.length>0?a[0]:System.getProperty("user.home")+"/mainctrl_inventory.txt");
    List<Function> fs = new ArrayList<>();
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) fs.add(f);
    fs.sort(Comparator.comparingLong((Function f)->f.getBody().getNumAddresses()).reversed());
    try (PrintWriter w = new PrintWriter(out,"UTF-8")) {
      w.printf("Program: %s%n", currentProgram.getName());
      w.printf("Language: %s%n", currentProgram.getLanguageID());
      w.printf("Image base: %s%n", currentProgram.getImageBase());
      w.printf("Entry/exec range: %s%n", currentProgram.getMemory());
      w.printf("Total functions: %d%n%n", fs.size());
      w.println("== 40 largest functions (addr  size  name) ==");
      for (int i=0;i<Math.min(40,fs.size());i++){
        Function f=fs.get(i);
        w.printf("%s  %6d  %s%n", f.getEntryPoint(), f.getBody().getNumAddresses(), f.getName());
      }
      w.println();
      w.println("== functions with interesting names ==");
      String re="(?i).*(auth|login|passw|reset|restore|factory|upgrade|update|fota|cota|mqtt|onvif|user|crypt|md5|verify|super|sadp|limitip|cloud|danale).*";
      for (Function f: currentProgram.getFunctionManager().getFunctions(true))
        if (f.getName().matches(re)) w.printf("%s  %s%n", f.getEntryPoint(), f.getName());
    }
    println("Wrote "+out.getAbsolutePath());
  }
}
