// Ghidra 12.1.4 headless script: targeted, read-only Nuitka PE attribution.
// Does not modify program bytes, execute target, contact services or use vehicles.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class LixiangNativeRefs extends GhidraScript {
    private static final String[] CODE = {
        "0x14073e1ab",
        "0x140741866",
        "0x140742a89",
        "0x1407432ea",
        "0x14074735c",
        "0x140751455",
        "0x14078807e",
        "0x1407a7545"
    };
    private static final String[] DATA = {
        "0x14122f238",
        "0x14122f220",
        "0x14122f2a8"
    };

    private Address address(String hex) {
        try {
            return currentProgram.getAddressFactory().getAddress(hex);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args=getScriptArgs();
        if (args.length != 1) {
            println("Expected one output path argument");
            return;
        }
        Path dest=Paths.get(args[0]);
        if (dest.getParent()!=null) Files.createDirectories(dest.getParent());
        try (BufferedWriter out=Files.newBufferedWriter(dest,StandardCharsets.UTF_8)) {
            out.write("Ghidra 12.1.4 read-only attribution report\n");
            out.write("Program: " + currentProgram.getName() + "\n");
            out.write("Image base: " + currentProgram.getImageBase() + "\n");
            out.write("Function count: " + currentProgram.getFunctionManager().getFunctionCount() + "\n");
            out.write("Note: partial/timeout analysis may mean no functions recognized.\n");
            for (String hex : CODE) {
                if (monitor.isCancelled()) break;
                Address addr=address(hex);
                if (addr==null) {
                    out.write("CODE " + hex + " invalid_address\n");
                    continue;
                }
                Function f=currentProgram.getFunctionManager().getFunctionContaining(addr);
                Instruction ins=currentProgram.getListing().getInstructionContaining(addr);
                out.write("CODE " + hex + " function=" +
                    (f==null?"UNRESOLVED":f.getEntryPoint()+" name="+f.getName())+
                    " instruction=" + (ins==null?"UNRESOLVED":ins.getMnemonicString())+"\n");
            }
            for (String hex : DATA) {
                if (monitor.isCancelled()) break;
                Address addr=address(hex);
                if (addr==null) continue;
                ReferenceIterator iter=currentProgram.getReferenceManager().getReferencesTo(addr);
                int count=0;
                while (iter.hasNext() && count<30) {
                    Reference ref=iter.next();
                    Function f=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    out.write("DATA " + hex + " from="+ref.getFromAddress()+
                        " type="+ref.getReferenceType()+
                        " function="+(f==null?"UNRESOLVED":f.getEntryPoint())+"\n");
                    count++;
                }
                out.write("DATA "+hex+" reference_count_observed="+count+" (capped 30)\n");
            }
        }
    }
}
