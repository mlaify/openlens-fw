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

public class DecompileCallersAt extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        Address target = toAddr(args[0]);
        Set<Function> callers = new LinkedHashSet<>();
        for (Reference reference : getReferencesTo(target)) {
            Function caller = getFunctionContaining(reference.getFromAddress());
            if (caller != null) callers.add(caller);
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new File(args[1]), "UTF-8")) {
            out.printf("Target %s; callers %d%n", target, callers.size());
            for (Function caller : callers) {
                DecompileResults result = decompiler.decompileFunction(caller, 120, monitor);
                out.printf("%n===== %s @ %s =====%n", caller.getName(), caller.getEntryPoint());
                out.println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : result.getErrorMessage());
            }
        }
        decompiler.dispose();
    }
}
