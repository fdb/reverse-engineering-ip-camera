//@category Analysis
//@description Decompile PunchTo and related Kalay packet-building functions
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompilePunchTo extends GhidraScript {

    // Function names (substrings) we want to decompile, in priority order.
    private static final String[] TARGETS = {
        "Write_PunchTo",
        "Send_PunchTo",
        "Write_P2PReq",
        "Send_P2PReq",
        "Write_DevLgn",   // known reference for calibration
        "Write_ReportSessionRdy",
        "Send_ReportSessionRdy",
        "Proto_Write_Header",
        "Proto_Read_Header",
        "PPPP_DecodeString",
        "PPPP_CRCEnc",
        "PPPP_CRCDec",
        "PPPP_Proto_Write_TryLanTcp",
        "PPPP_Proto_Read_TryLanTcp",
        "PPPP_Proto_Send_PunchTo",
    };

    @Override
    public void run() throws Exception {
        String outPath = "/tmp/ghidra-cam/decompile.txt";
        try {
            new java.io.File("/tmp/ghidra-cam").mkdirs();
        } catch (Exception e) { /* ignore */ }

        PrintWriter out = new PrintWriter(new FileWriter(outPath));
        out.println("=== Ghidra decompile output ===");
        out.println("Program: " + currentProgram.getName());
        out.println();

        DecompInterface decomp = new DecompInterface();
        decomp.setOptions(new DecompileOptions());
        decomp.openProgram(currentProgram);

        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();

        int total = 0;
        for (String needle : TARGETS) {
            out.println("────────────────────────────────────────────────────────────");
            out.println("  Hunting: *" + needle + "*");
            out.println("────────────────────────────────────────────────────────────");

            boolean found = false;
            SymbolIterator it = st.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                String name = s.getName();
                if (!name.contains(needle)) continue;
                Function f = fm.getFunctionAt(s.getAddress());
                if (f == null) continue;
                found = true;
                total++;
                out.println();
                out.println(">>> " + f.getName() + "  @ " + f.getEntryPoint());
                out.println(">>> signature: " + f.getSignature());
                out.println(">>> body size: " + f.getBody().getNumAddresses() + " bytes");
                out.println();
                try {
                    DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                    if (res != null && res.getDecompiledFunction() != null) {
                        out.println(res.getDecompiledFunction().getC());
                    } else {
                        out.println("(decompile returned null)");
                    }
                } catch (Exception e) {
                    out.println("(decompile error: " + e.getMessage() + ")");
                }
                out.println();
            }
            if (!found) {
                out.println("  (no symbol matched)");
            }
            out.println();
        }

        out.println("=== Decompiled " + total + " functions ===");
        out.close();
        println("Decompile output saved to " + outPath);
    }
}
