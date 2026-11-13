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

public class TraceGlobal extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        Address target = toAddr(args[0]);
        Set<Function> functions = new LinkedHashSet<>();
        try (PrintWriter out = new PrintWriter(new File(args[1]), "UTF-8")) {
            out.printf("References to %s in %s%n", target, currentProgram.getName());
            for (Reference ref : getReferencesTo(target)) {
                Address from = ref.getFromAddress();
                out.printf("direct %s %s%n", from, ref.getReferenceType());
                Function f = getFunctionContaining(from);
                if (f != null) functions.add(f);
                for (Reference indirect : getReferencesTo(from)) {
                    Address from2 = indirect.getFromAddress();
                    out.printf("  indirect %s %s%n", from2, indirect.getReferenceType());
                    Function f2 = getFunctionContaining(from2);
                    if (f2 != null) functions.add(f2);
                }
            }
            DecompInterface dec = new DecompInterface();
            dec.openProgram(currentProgram);
            try {
                for (Function f : functions) {
                    out.printf("%n===== %s @ %s =====%n", f.getName(), f.getEntryPoint());
                    DecompileResults result = dec.decompileFunction(f, 120, monitor);
                    out.println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : result.getErrorMessage());
                }
            } finally { dec.dispose(); }
        }
    }
}
