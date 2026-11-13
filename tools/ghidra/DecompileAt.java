// SPDX-License-Identifier: MIT
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.PrintWriter;

public class DecompileAt extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        Address address = toAddr(args[0]);
        Function function = getFunctionContaining(address);
        if (function == null) throw new IllegalArgumentException("No function at " + address);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
        try (PrintWriter out = new PrintWriter(new File(args[1]), "UTF-8")) {
            out.printf("Function %s @ %s, containing %s%n", function.getName(), function.getEntryPoint(), address);
            out.println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : result.getErrorMessage());
        } finally {
            decompiler.dispose();
        }
    }
}
