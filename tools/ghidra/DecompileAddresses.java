// SPDX-License-Identifier: MIT
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.PrintWriter;

public class DecompileAddresses extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (int i = 1; i < args.length; i++) {
            Address address = toAddr(args[i]);
            Function function = getFunctionContaining(address);
            try (PrintWriter out = new PrintWriter(new File(args[0], args[i] + ".c"), "UTF-8")) {
                if (function == null) {
                    out.println("No function at " + address);
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
                out.printf("Function %s @ %s%n", function.getName(), function.getEntryPoint());
                out.println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : result.getErrorMessage());
            }
        }
        decompiler.dispose();
    }
}
