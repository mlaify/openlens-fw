// SPDX-License-Identifier: MIT
// Lists every ioctl() call site with its request code, when the decompiler resolves it to a
// constant (handles PLT thunks). One TSV line per call: function, entry, callsite, request,
// dir, type, nr, size, and the first "MI_*" string the function references (names stripped
// wrappers by their log strings). Args: <output.tsv>
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.io.File;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

public class IoctlInventory extends GhidraScript {
  private boolean isIoctl(Function c) {
    if (c == null) return false;
    String n = c.getName();
    if (c.isThunk() && c.getThunkedFunction(true) != null) n = c.getThunkedFunction(true).getName();
    return n.equals("ioctl") || c.getName().equals("ioctl");
  }

  // Follow simple copies/casts back to a constant, a few steps deep.
  private Long constOf(Varnode v, int depth) {
    if (v == null || depth > 6) return null;
    if (v.isConstant()) return v.getOffset() & 0xffffffffL;
    PcodeOp d = v.getDef();
    if (d == null) return null;
    int op = d.getOpcode();
    if (op == PcodeOp.COPY || op == PcodeOp.CAST || op == PcodeOp.INT_ZEXT || op == PcodeOp.INT_SEXT)
      return constOf(d.getInput(0), depth + 1);
    return null;
  }

  // First string starting with "MI_" referenced from the function body (e.g. __FUNCTION__ in a log).
  private String miName(Function f) {
    for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
      for (Reference ref : ins.getReferencesFrom()) {
        Data d = getDataAt(ref.getToAddress());
        if (d == null || !d.hasStringValue()) continue;
        Object v = d.getValue();
        if (v instanceof String && ((String) v).startsWith("MI_")) return (String) v;
      }
    }
    return "";
  }

  @Override protected void run() throws Exception {
    String[] a = getScriptArgs();
    Set<Function> callers = new LinkedHashSet<>();
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
      if (isIoctl(f)) continue;
      for (Function c : f.getCalledFunctions(monitor)) if (isIoctl(c)) { callers.add(f); break; }
    }
    DecompInterface dec = new DecompInterface(); dec.openProgram(currentProgram);
    int n = 0, unresolved = 0;
    try (PrintWriter out = new PrintWriter(new File(a[0]), "UTF-8")) {
      out.println("function\tentry\tcallsite\trequest\tdir\ttype\tnr\tsize\tmi_name");
      for (Function f : callers) {
        DecompileResults r = dec.decompileFunction(f, 60, monitor);
        HighFunction hf = r.getHighFunction();
        String mi = miName(f);
        if (hf == null) { out.printf("%s\t%s\t-\tDECOMPILE_FAILED\t\t\t\t\t%s%n", f.getName(), f.getEntryPoint(), mi); continue; }
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext()) {
          PcodeOpAST op = it.next();
          if (op.getOpcode() != PcodeOp.CALL) continue;
          Address t = op.getInput(0).getAddress();
          Function callee = getFunctionAt(t);
          if (!isIoctl(callee)) continue;
          Address site = op.getSeqnum().getTarget();
          Long req = op.getNumInputs() > 2 ? constOf(op.getInput(2), 0) : null;
          if (req == null) { unresolved++; out.printf("%s\t%s\t%s\tUNRESOLVED\t\t\t\t\t%s%n", f.getName(), f.getEntryPoint(), site, mi); continue; }
          long v = req;
          out.printf("%s\t%s\t%s\t0x%08x\t%d\t0x%02x\t%d\t%d\t%s%n", f.getName(), f.getEntryPoint(), site, v,
                     (v >>> 30) & 3, (v >>> 8) & 0xff, v & 0xff, (v >>> 16) & 0x3fff, mi);
          n++;
        }
      }
    } finally { dec.dispose(); }
    println("Wrote " + a[0] + ": " + n + " resolved, " + unresolved + " unresolved, " + callers.size() + " callers");
  }
}
