// SPDX-License-Identifier: MIT
// For every function that calls ioctl(), find the helper it calls that open()s a device, and
// recover that helper's path string by folding the decompiler's address arithmetic
// (constant / literal-pool LOAD + constant / PTRSUB). Lets stripped MI wrappers be grouped by
// module (/dev/mi_vif, /dev/mi_venc, ...). TSV: caller, getter, path. Args: <output.tsv>
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.io.File;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class IoctlDeviceMap extends GhidraScript {
  private DecompInterface dec;
  private final Map<Function, String> getterPath = new HashMap<>();

  private String calleeName(Function c) {
    if (c == null) return "";
    if (c.isThunk() && c.getThunkedFunction(true) != null) return c.getThunkedFunction(true).getName();
    return c.getName();
  }

  // Fold a varnode to a constant value where it's built from constants and loads of constants.
  private Long fold(Varnode v, int depth) throws Exception {
    if (v == null || depth > 10) return null;
    if (v.isConstant()) return v.getOffset() & 0xffffffffL;
    if (v.isAddress() && v.getSize() == 4) {          // direct memory word
      return (long) getInt(v.getAddress()) & 0xffffffffL;
    }
    PcodeOp d = v.getDef();
    if (d == null) return null;
    switch (d.getOpcode()) {
      case PcodeOp.COPY: case PcodeOp.CAST: case PcodeOp.INT_ZEXT: case PcodeOp.INT_SEXT:
        return fold(d.getInput(0), depth + 1);
      case PcodeOp.INT_ADD: case PcodeOp.PTRSUB: case PcodeOp.PTRADD: {
        Long a = fold(d.getInput(0), depth + 1), b = fold(d.getInput(1), depth + 1);
        if (a == null || b == null) return null;
        long r = a + b;
        if (d.getOpcode() == PcodeOp.PTRADD && d.getNumInputs() > 2) {
          Long s = fold(d.getInput(2), depth + 1); if (s == null) return null; r = a + b * s;
        }
        return r & 0xffffffffL;
      }
      case PcodeOp.LOAD: {
        Long p = fold(d.getInput(1), depth + 1);
        if (p == null) return null;
        Address ad = toAddr(p);
        return (long) getInt(ad) & 0xffffffffL;
      }
      default: return null;
    }
  }

  private String cstring(long addr) {
    try {
      StringBuilder sb = new StringBuilder();
      Address a = toAddr(addr);
      for (int i = 0; i < 64; i++) {
        byte b = getByte(a.add(i));
        if (b == 0) break;
        if (b < 0x20 || b > 0x7e) return null;
        sb.append((char) b);
      }
      return sb.length() > 0 ? sb.toString() : null;
    } catch (Exception e) { return null; }
  }

  // Path opened by this function, if it calls open() with a resolvable string.
  private String openedPath(Function g) throws Exception {
    if (getterPath.containsKey(g)) return getterPath.get(g);
    String found = null;
    boolean callsOpen = false;
    for (Function c : g.getCalledFunctions(monitor)) if (calleeName(c).equals("open")) callsOpen = true;
    if (callsOpen) {
      DecompileResults r = dec.decompileFunction(g, 60, monitor);
      HighFunction hf = r.getHighFunction();
      if (hf != null) {
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext() && found == null) {
          PcodeOpAST op = it.next();
          if (op.getOpcode() != PcodeOp.CALL) continue;
          if (!calleeName(getFunctionAt(op.getInput(0).getAddress())).equals("open")) continue;
          Long p = op.getNumInputs() > 1 ? fold(op.getInput(1), 0) : null;
          found = p == null ? "UNRESOLVED_OPEN" : String.valueOf(cstring(p));
        }
      }
    }
    getterPath.put(g, found);
    return found;
  }

  @Override protected void run() throws Exception {
    String[] a = getScriptArgs();
    dec = new DecompInterface(); dec.openProgram(currentProgram);
    int n = 0;
    try (PrintWriter out = new PrintWriter(new File(a[0]), "UTF-8")) {
      out.println("caller\tgetter\tpath");
      for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        boolean callsIoctl = false;
        for (Function c : f.getCalledFunctions(monitor)) if (calleeName(c).equals("ioctl") && !f.getName().equals("ioctl")) callsIoctl = true;
        if (!callsIoctl) continue;
        String getter = "-", path = "";
        for (Function c : f.getCalledFunctions(monitor)) {
          String p = openedPath(c);
          if (p != null) { getter = c.getEntryPoint().toString(); path = p; break; }
        }
        if (path.isEmpty()) { String p = openedPath(f); if (p != null) { getter = "self"; path = p; } }
        out.printf("%s\t%s\t%s%n", f.getEntryPoint(), getter, path);
        n++;
      }
    } finally { dec.dispose(); }
    println("Wrote " + a[0] + ": " + n + " ioctl callers");
  }
}
