// SPDX-License-Identifier: MIT
// Disassemble whole functions by address: args = <out file> <hex addr>... (static only).
// For values the decompiler drops (e.g. a byte stored to the stack and passed to write()).
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import java.io.File;
import java.io.PrintWriter;

public class DisassembleAt extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    try (PrintWriter out = new PrintWriter(new File(args[0]), "UTF-8")) {
      for (int i = 1; i < args.length; i++) {
        Address a = toAddr(Long.parseLong(args[i].replace("0x", ""), 16));
        Function f = getFunctionContaining(a);
        if (f == null) { out.println("== no function at " + args[i]); continue; }
        out.println("== " + f.getName() + " @ " + f.getEntryPoint());
        for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
          out.println("  " + ins.getAddress() + "  " + ins);
        }
        out.println();
      }
    }
    println("Wrote " + args[0]);
  }
}
