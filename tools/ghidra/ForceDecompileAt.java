// SPDX-License-Identifier: MIT
//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.PrintWriter;

public class ForceDecompileAt extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        Address address = toAddr(args[0]);
        if (getInstructionAt(address) == null) disassemble(address);
        Function function = getFunctionContaining(address);
        if (function == null) function = createFunction(address, "recovery_initializer");
        if (function == null) throw new IllegalStateException("Could not create function at " + address);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
        try (PrintWriter out = new PrintWriter(new File(args[1]), "UTF-8")) {
            out.printf("Function %s @ %s%n", function.getName(), function.getEntryPoint());
            out.println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : result.getErrorMessage());
        } finally { decompiler.dispose(); }
    }
}
