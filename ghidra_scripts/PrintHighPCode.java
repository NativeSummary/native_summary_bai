/* ###
 * Ghostrings
 * Copyright (C) 2022  NCC Group
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * https://github.com/nccgroup/ghostrings/blob/main/ghidra_scripts/PrintHighPCode.java
 */
//Print high P-Code for currently selected function, with simplification style selector
//@author James Chambers <james.chambers@nccgroup.com>
//@category _NativeSummary
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.exception.CancelledException;
import org.example.nativesummary.util.PcodePrettyPrinter;

public class PrintHighPCode extends GhidraScript {
    // Groups / root actions: firstpass, register, paramid, normalize,
    // jumptable, decompile
    public static final String[] SIMPLIFICATION_STYLES = new String[] {
            "decompile",
            "jumptable",
            "normalize",
            "paramid",
            "register",
            "firstpass"
    };

    public DecompInterface decompIfc;

    public DecompInterface setUpDecompiler(String simplificationStyle) {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options = new DecompileOptions();

        PluginTool tool = state.getTool();
        if (tool != null) {
            OptionsService service = tool.getService(OptionsService.class);
            if (service != null) {
                ToolOptions opt = service.getOptions("Decompiler");
                options.grabFromToolAndProgram(null, opt, currentProgram);
            }
        }

        options.setEliminateUnreachable(false);

        decompInterface.setOptions(options);
        decompInterface.toggleCCode(false);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.toggleParamMeasures(false);
        decompInterface.setSimplificationStyle(simplificationStyle);

        return decompInterface;
    }

    public HighFunction decompileFunction(Function func) {
        HighFunction highFunc = null;

        try {
            DecompileResults results = decompIfc.decompileFunction(
                    func,
                    decompIfc.getOptions().getDefaultTimeout(),
                    monitor);

            // Docs suggest calling this after every decompileFunction call
            decompIfc.flushCache();

            highFunc = results.getHighFunction();

            String decompError = results.getErrorMessage();
            if (decompError != null && decompError.length() > 0) {
                printf("Decompiler error for %s: %s\n", funcNameAndAddr(func),
                        decompError.trim());
            }

            if (!results.decompileCompleted()) {
                printf("Decompilation not completed for %s\n", funcNameAndAddr(func));
                return null;
            }
        } catch (Exception e) {
            println("Decompiler exception:");
            e.printStackTrace();
        }

        return highFunc;
    }

    public String askStyleChoice() throws CancelledException {
        final List<String> choices = Arrays.asList(SIMPLIFICATION_STYLES);
        return askChoice("PCode Dump", "Select simplification style", choices,
                SIMPLIFICATION_STYLES[0]);
    }

    @Override
    protected void run() throws Exception {
        // Check currently selected function
        Function func = getFunctionContaining(currentAddress);
        if (func == null) {
            final String msg = "No function selected";
            println(msg);
            popup(msg);
            return;
        }

        final String styleChoice = askStyleChoice();
        decompIfc = setUpDecompiler(styleChoice);

        if (!decompIfc.openProgram(currentProgram)) {
            println("Decompiler could not open program");
            final String lastMsg = decompIfc.getLastMessage();
            if (lastMsg != null) {
                printf("Decompiler last message: %s\n", lastMsg);
            }
            decompIfc.stopProcess();
            return;
        }

        final boolean xmlDumpEnabled = askYesNo("Save XML dump?",
                "Save decompiler IPC XML dump for debugging?");
        if (xmlDumpEnabled) {
            try {
                final File debugDump = askFile("Decompiler IPC XML Dump", "Save");
                decompIfc.enableDebug(debugDump);
                printf("Saving decompiler IPC XML dump to %s\n", debugDump.getPath());
            } catch (CancelledException e) {
                println("XML dump save cancelled");
            }
        }

        printf("PCode for function %s (simplification style: %s)\n",
                funcNameAndAddr(func),
                styleChoice);

        HighFunction highFunc = decompileFunction(func);
        if (highFunc == null) {
            println("Failed to decompile function");
            decompIfc.stopProcess();
            return;
        }

        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        PcodePrettyPrinter pp = new PcodePrettyPrinter(getCurrentProgram());
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();

            printf("0x%x:0x%02x\t%s\n",
                    pcodeOpAST.getSeqnum().getTarget().getOffset(),
                    pcodeOpAST.getSeqnum().getTime(), pp.printOne(pcodeOpAST));
        }

        decompIfc.stopProcess();
    }

    public String funcNameAndAddr(Function func) {
        return String.format(
                "%s @ %s",
                getFuncName(func),
                func.getEntryPoint().toString());
    }

    public String getFuncName(Function func) {
        if (func.getName() != null)
            return func.getName();
        return "(undefined)";
    }
}