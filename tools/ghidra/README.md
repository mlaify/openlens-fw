# Ghidra headless scripts

Generic decompile/trace helpers used for the static analysis behind `docs/BOARD.md` and the
disclosure work. Run them with `scripts/ghidra-run.sh` (handles the sandbox env and project
dir), or directly with `analyzeHeadless … -scriptPath tools/ghidra -postScript <Script> <args>`.

All target the ARM binaries in this firmware: `-processor ARM:LE:32:v8`. Ghidra maps ELF
images at base 0x10000, so **a Ghidra address = file/ELF vaddr + 0x10000** for these
binaries — and shared libraries' symbol values (from `objdump -T`) need the same +0x10000.
When in doubt, use the by-name or by-string scripts, which don't depend on addresses.

| Script | Args | Output |
|---|---|---|
| `DecompileByName.java` | `<out.c> <name>…` | Decompiles functions by exact symbol name (best for `.so` exports) |
| `DecompileStringRefs.java` | `<out.c> <substring>…` | Decompiles every function referencing a string containing the substring (best for stripped binaries with log strings) |
| `DecompileAddresses.java` | `<outdir> <addr>…` | One `<addr>.c` per address (outdir must exist) |
| `DecompileAt.java` | `<addr> <out.c>` | Function containing the address |
| `ForceDecompileAt.java` | `<addr> <out.c>` | Same, creating a function first if Ghidra missed it |
| `DecompileCallersAt.java` | `<addr> <out.c>` | All callers of the function at the address |
| `DecompileCallersByName.java` | `<out.c> <name>…` | Callers of named functions, thunk/PLT-aware |
| `DecompileCallersOfSymbol.java` | `<out.c> <symbol>…` | Callers of external/imported symbols |
| `TraceFunction.java` | `<addr> <out>` | Callers + call sites of a function |
| `TraceGlobal.java` | `<addr> <out>` | References to a global |
| `FunctionInventory.java` | `<out.txt>` | Every function with size/name |
| `ThumbDecompileAt.java` | `<out.c> <addr>…` | Forces Thumb mode, disassembles, creates + decompiles the function and its direct callees (raw Thumb-2 images) |
| `EnableAggressiveArm.java` | (pre-script, no args) | Turns on the ARM aggressive instruction finder for raw images |
| `IoctlDeviceMap.java` | `<out.tsv>` | For each ioctl caller, the helper that `open()`s a device and the folded path (`/dev/mi_vif`…), to group stripped MI wrappers by module |
| `CommonCallers.java` | `<out.txt> <depth> <addr>…` | Functions that reach the most targets upward within N levels (finds the routine driving a call sequence) |
| `IoctlInventory.java` | `<out.tsv>` | Every `ioctl()` call site with its constant request code decoded (dir/type/nr/size), plus the first `MI_*` string the function references (labels stripped wrappers). Used for `analysis/*-mi-ioctl-inventory.tsv` |

Companion: `scripts/resolve-dat-strings.py <elf> <decompiled.c>` resolves `DAT_` literal-pool
words in Ghidra output to the log strings they point to (ET_EXEC addresses are unshifted; only
`.so` files get the +0x10000).

Gotchas learned the hard way:
- `DecompileAddresses` takes an output **directory**; `DecompileAt`/`DecompileCallersAt` take
  the **address first**, then the output file.
- radare2 `aae` does not resolve ARM movw/movt string loads in these binaries — use
  `DecompileStringRefs` instead. objdump mis-decodes the ARM/Thumb mix; don't trust its
  zero-call-site counts.
- Very large functions (≈50 KB) can exceed the decompiler's response buffer.

## Raw kernel recipe (stock kernel is a **Thumb-2** Image)
The stock kernel starts with `add r9, pc, #1; bx r9` (switch to Thumb), so decode it as Thumb.
Get the Image with `scripts/extract-kernel-dtb.py`, find function addresses by locating the
Thumb `ldr` that loads a pointer to a known string (virtual base **0xC0008000** — confirmed by
pointers to the IRLED strings), then:

    analyzeHeadless "$P" k -import kernel.bin -loader BinaryLoader -loader-baseAddr 0xC0008000 \
      -processor ARM:LE:32:v7 -noanalysis -scriptPath tools/ghidra \
      -postScript ThumbDecompileAt.java out.c 0xc0305c3c

Data the decompiler shows as `_DAT_xxxxxxxx` is readable straight from the Image at
`va - 0xC0008000` (that's how the IRLED GPIO table was read).
