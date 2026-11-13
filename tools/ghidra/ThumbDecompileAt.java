// SPDX-License-Identifier: MIT
// Decompiles functions at given addresses in a raw image, forcing Thumb mode (TMode=1)
// first — for Thumb-2 kernels loaded with BinaryLoader, where auto-analysis decodes ARM.
// Also decompiles each function's direct callees (one level), where constants such as
// GPIO numbers are usually passed. Run with -noanalysis for speed.
// Args: <output.c> <addr> [<addr> ...]
//@category Analysis
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.LinkedHashSet;
import java.util.Set;

public class ThumbDecompileAt extends GhidraScript {
  private Function thumbFunctionAt(Address a) throws Exception {
    Function f = getFunctionAt(a);
    if (f != null) return f;
    Register t = currentProgram.getRegister("TMode");
    currentProgram.getProgramContext().setRegisterValue(a, a.add(0x4000),
        new RegisterValue(t, BigInteger.ONE));
    new DisassembleCommand(a, new AddressSet(a, a.add(0x4000)), true).applyTo(currentProgram, monitor);
    return createFunction(a, null);
  }

  @Override protected void run() throws Exception {
    String[] args = getScriptArgs();
    Set<Function> todo = new LinkedHashSet<>();
    for (int i = 1; i < args.length; i++) {
      Function f = thumbFunctionAt(toAddr(args[i]));
      if (f == null) { println("could not create function at " + args[i]); continue; }
      todo.add(f);
      for (Function c : f.getCalledFunctions(monitor)) todo.add(c);
    }
    DecompInterface dec = new DecompInterface();
    dec.openProgram(currentProgram);
    try (PrintWriter out = new PrintWriter(new File(args[0]), "UTF-8")) {
      for (Function f : todo) {
        DecompileResults r = dec.decompileFunction(f, 120, monitor);
        out.println("/* ===== " + f.getName() + " @ " + f.getEntryPoint() + " ===== */");
        out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC()
                                           : "/* decompile failed: " + r.getErrorMessage() + " */");
      }
    }
    println("Wrote " + args[0] + " (" + todo.size() + " functions)");
  }
}
