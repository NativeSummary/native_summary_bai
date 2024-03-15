package org.example.nativesummary.env.funcs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.KSet;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

import java.util.*;

import static com.bai.env.funcs.externalfuncs.VarArgsFunctionBase.getVarArgsSignature;
import static com.bai.env.funcs.externalfuncs.VarArgsFunctionBase.writeSignature;

public class CLibraryFunctions extends JNIFunctionBase {
    // exit memset __aeabi_memcpy
    private static final String[] syms = {"exit", "open", "close", "write", "clock",
            "remove", "usleep", "stat", "access",
//            "fputc", "ungetc", too much taint
            "fopen", "fclose", "fread", "fputs",//"fseek", "ftell", "lseek", "fseeko", "ftello",
            "flock", "opendir", "readdir", "getpid", "getppid", "kill",
            "prctl", "pipe", "fork", "waitpid", "execlp", "raise",
            "puts", "printf", "sprintf", "snprintf", "fprintf", "scanf", "__iso99_scanf", "sscanf", "__iso99_sscanf", "fscanf", "__isoc99_fscanf", "vprintf", "vfprintf",
            "strchr", "strdup",
            "__aeabi_memclr4", "__aeabi_memclr", "__aeabi_memclr8",
            "__vsprintf_chk",
            "eventfd", "poll",
            "bufferevent_socket_new", "bufferevent_new", "curl_easy_setopt", "curl_easy_init"};

    private static final Set<String> staticSymbols = new HashSet<>(List.of(syms));

    public static final String[] syms2 = {"bufferevent_socket_new", "bufferevent_new", "curl_easy_setopt", "curl_easy_init"};
    public static final Set<String> nonExternals = new HashSet<>(List.of(syms2));

    // not print warning when symbols are not modeled
    // because these functions is not helpful to dataflow analysis, and is too verbose.
    private static final String[] symsNoModel = {"__stack_chk_fail",
            "fseek", "ftell", "lseek", "fseeko", "ftello",
            };
    public static final Set<String> noModelSymbols = new HashSet<>(List.of(symsNoModel));

    public CLibraryFunctions() {
        super(staticSymbols);
    }

    public static CLibraryFunctions instance = new CLibraryFunctions();

    public static CLibraryFunctions getInstance() {
        return instance;
    }

    private static Map<String, Integer> initFormatMap() {
        Map<String, Integer> map = new HashMap<>();
        map.put("__vsprintf_chk", 3);
        map.put("fprintf", 1);
        map.put("fscanf", 1);
        map.put("printf", 0);
        map.put("scanf", 0);
        map.put("snprintf", 2);
        map.put("sprintf", 1);
        map.put("sscanf", 1);
        map.put("vscanf", 0);
        return Collections.unmodifiableMap(map);
    }
    // map from format string related api to the arg index of format string
    public static final Map<String, Integer> formatMap = initFormatMap();

    public void processVarArgsSignature(PcodeOp pcode, AbsEnv absEnv, Function calleeFunc) {
        int formatStringParamIndex = -1;
        if (formatMap.containsKey(calleeFunc.getName())) {
            formatStringParamIndex = formatMap.get(calleeFunc.getName());
        } else {
            return;
        }
        String fmtString = null;
        int maxSpecifier = 0;
        KSet bufPtrKSet = getParamKSet(calleeFunc, formatStringParamIndex, absEnv);
        if (bufPtrKSet.isTop()) {
            return;
        }
        for (AbsVal fmtPtr : bufPtrKSet) {
            String tmp = StringUtils.getString(fmtPtr, absEnv);
            if (tmp != null && tmp.chars().filter(ch -> ch == '%').count() > maxSpecifier) {
                fmtString = tmp;
            }
        }
        if (fmtString == null) {
            Logging.info("Fail to get the format string from arg" + formatStringParamIndex + " @ "
                    + Utils.getAddress(pcode));
            return;
        } else {
            Logging.info("Overriding the call signature at:" + formatStringParamIndex + " @ "
                    + Utils.getAddress(pcode) +" according to the format string: " + fmtString);
        }
        FunctionDefinition functionDefinition = getVarArgsSignature(Utils.getAddress(pcode));
        if (functionDefinition == null) {
            functionDefinition = defineVarArgsSignature(calleeFunc, Utils.getAddress(pcode), fmtString);
        }
    }

    FunctionDefinition defineVarArgsSignature(Function callee, Address address, String format) {
        try {
            final int tid = GlobalState.currentProgram.startTransaction("define vargs signature");
            final FunctionDefinition functionDefinition = StringUtils.getFunctionSignature(format, callee);
            Function caller = GlobalState.flatAPI.getFunctionContaining(address);
            if (caller != null) {
                writeSignature(caller, address, functionDefinition);
            }
            GlobalState.currentProgram.endTransaction(tid, true);
            return functionDefinition;
        } catch (Exception e) {
            Logging.error("Fail to define signature for " + callee);
            e.printStackTrace();
        }
        return null;
    }
}
