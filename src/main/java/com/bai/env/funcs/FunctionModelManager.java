package com.bai.env.funcs;

import com.bai.env.funcs.externalfuncs.AtoiFunction;
import com.bai.env.funcs.externalfuncs.CallocFunction;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.funcs.externalfuncs.FgetcFunction;
import com.bai.env.funcs.externalfuncs.FgetsFunction;
import com.bai.env.funcs.externalfuncs.FreeFunction;
import com.bai.env.funcs.externalfuncs.GetcFunction;
import com.bai.env.funcs.externalfuncs.GetenvFunction;
import com.bai.env.funcs.externalfuncs.GetsFunction;
import com.bai.env.funcs.externalfuncs.LibcStartMainFunction;
import com.bai.env.funcs.externalfuncs.MallocFunction;
import com.bai.env.funcs.externalfuncs.MallocUsableSizeFunction;
import com.bai.env.funcs.externalfuncs.MemcpyFunction;
import com.bai.env.funcs.externalfuncs.RandFunction;
import com.bai.env.funcs.externalfuncs.ReadFunction;
import com.bai.env.funcs.externalfuncs.ReallocFunction;
import com.bai.env.funcs.externalfuncs.RecvFunction;
import com.bai.env.funcs.externalfuncs.StrcatFunction;
import com.bai.env.funcs.externalfuncs.StrcpyFunction;
import com.bai.env.funcs.externalfuncs.StrlenFunction;
import com.bai.env.funcs.externalfuncs.StrncpyFunction;
import com.bai.env.funcs.externalfuncs.TopResultFunction;
import com.bai.env.funcs.stdfuncs.CppStdModelBase;
import com.bai.env.funcs.stdfuncs.ListModel;
import com.bai.env.funcs.stdfuncs.MapModel;
import com.bai.env.funcs.stdfuncs.VectorModel;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import org.example.nativesummary.env.funcs.CLibraryFunctions;
import org.example.nativesummary.env.funcs.JNIFunctionBase;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * FunctionModelManager
 */
public class FunctionModelManager {

    private static final List<ExternalFunctionBase> EXTERNAL_FUNCTION_LIST = List.of(
            new LibcStartMainFunction(),
            new TopResultFunction(),
            // Heap function
            new MallocFunction(),
            new CallocFunction(),
            new ReallocFunction(),
            new FreeFunction(),
            new MallocUsableSizeFunction(),
            // String function
            new StrcatFunction(),
            new StrlenFunction(),
            new StrcpyFunction(),
            new StrncpyFunction(),
            // Taint source functions
            new GetcFunction(),
            new FgetcFunction(),
            new GetsFunction(),
            new FgetsFunction(),
            new ReadFunction(),
            new RecvFunction(),
            new GetenvFunction(),
            new RandFunction(),
// Too Complex to model
//            // Taint source functions with varargs
//            new ScanfFunction(),
//            new SscanfFunction(),
//            new FscanfFunction(),
//            new StrchrFunction(),
//            // varargs functions
//            new PrintfFunction(),
//            new SnprintfFunction(),
//            new FprintfFunction(),
//            new SprintfFunction(),
            // stdlib
            new MemcpyFunction(),
            new AtoiFunction(),
//            new PutsFunction(),
            new JNIFunctionBase(),
            new CLibraryFunctions()
    );

    // std function that is hard to analyze.
    // Ghidra will demangle stdlib function
    private static final Set<String> stdFuncSet = new HashSet<>(List.of( "operator.new", "operator.new[]", "operator.delete", "operator.delete[]",
            // double underline
            "__cxa_guard_release", "__stack_chk_fail", "__do_date_order", "__throw_bad_alloc", "__execute", "__cxa_rethrow_primary_exception", "__cxa_get_exception_ptr", "__stage2_int_loop", "__cxa_deleted_virtual", "__check_grouping", "__cxa_current_primary_exception", "__isOurExceptionClass", "__install_ctor", "__on_zero_shared", "__throw_out_of_range", "__cxa_uncaught_exceptions", "__cxa_get_globals_fast", "__stage2_int_prep", "__setExceptionClass", "__thread_local_data", "__cxa_allocate_dependent_exception", "__cxa_begin_catch", "__cxa_free_exception", "__cxa_get_globals", "__cxa_free_dependent_exception", "__register_atfork", "__cxa_guard_abort", "__set_badbit_and_consider_rethrow", "__cxa_pure_virtual", "__cxa_rethrow", "__cxa_finalize", "__cxa_increment_exception_refcount", "__set_failbit_and_consider_rethrow", "__ctype_get_mb_cur_max", "__cxa_uncaught_exception", "__cxa_atexit", "__grow_by_and_replace", "__stage2_float_prep", "__do_get_floating_point<double>", "__undeclare_reachable", "__getExceptionClass", "__do_put", "__throw_length_error", "__release_shared", "__thread_struct", "__stage2_float_loop", "__grow_by", "__global", "__throw_system_error", "__cxa_demangle", "__append_forward_unsafe<char*>", "__cxa_decrement_exception_refcount", "__call_once", "__do_get_unsigned<unsigned_short>", "__throw_runtime_error", "__make_ready_at_thread_exit", "__gxx_personality_v0", "__do_get_unsigned<unsigned_long_long>", "__get_deleter", "__cxa_allocate_exception", "__cxa_current_exception_type", "__cxa_throw", "__make_ready", "__cxa_guard_acquire", "__do_nothing", "__cxa_end_catch", "__cxa_call_unexpected", "__call_callbacks"));

    private static final List<String> stdNameSpaceStringList = List.of("std");
    private static final List<CppStdModelBase> STD_MODEL_LIST = List.of(
            new ListModel(),
            new MapModel(),
            new VectorModel()
    );

    private static final Pattern STL_MODEL_NAME_PATTERN = Pattern.compile("(\\w+)<.*allocator.*>");
    private static final Map<String, ExternalFunctionBase> symbol2ExternalFunctionMap = new HashMap<>();
    private static final Map<Address, String> address2SymbolConfigMap = new HashMap<>();
    private static final Map<String, CppStdModelBase> symbol2StdModelMap = new HashMap<>();


    private static void initSymbol2ExternalFunctionMap() {
        for (ExternalFunctionBase functionModel : EXTERNAL_FUNCTION_LIST) {
            for (String symbol : functionModel.getSymbols()) {
                if (symbol2ExternalFunctionMap.put(symbol, functionModel) != null) {
                    Logging.debug("\"" + symbol + "\"" + " already existed, please check.");
                }
            }
        }
    }

    private static void initSymbol2StdModelMap() {
        for (CppStdModelBase stdModel: STD_MODEL_LIST) {
            for (Object symbol: stdModel.getSymbols()) {
                if (symbol2StdModelMap.put((String) symbol, stdModel) != null) {
                    Logging.debug("C++ std::\"" + symbol + "\"" + " already existed, please check.");
                }
            }
        }
    }

    /**
     * Checks if a function is from C++ std library.
     * @param function the function.
     * @return true if it is from C++ std library, false otherwise.
     */
    public static boolean isStd(Function function) {
        if (stdFuncSet.contains(function.getName())) {
            return true;
        }
        Namespace namespace = function.getParentNamespace();
        if (namespace == null) {
            return false;
        }
        String namespaceString = namespace.getName(true);
        if (namespaceString == null) {
            return false;
        }
        for (String s : stdNameSpaceStringList) {
            if (namespaceString.startsWith(s)) {
                return true;
            }
        }
        return false;
    }

    /** Get registered external function model.
    * @param symbol the symbol string.
    * @return the external function model or null if not registered.
    */
    public static ExternalFunctionBase getExternalFunction(String symbol) {
        return symbol2ExternalFunctionMap.get(symbol);
    }

    /**
     * Register a mapping from address to symbol.
     * @param address the address.
     * @param symbol the symbol string.
     * @return the old symbol if address already registered, otherwise null.
     */
    public static String mapAddress2Symbol(Address address, String symbol) {
        return address2SymbolConfigMap.put(address, symbol);
    }

    /**
     * Checks if the function entry address is mapped to a symbol.
     * @param entryAddress the function entry address.
     * @return true if the address is mapped, otherwise false.
     */
    public static boolean isFunctionAddressMapped(Address entryAddress) {
        return address2SymbolConfigMap.containsKey(entryAddress);
    }

    /**
     * Reset the address to symbol mapping.
     */
    public static void resetConfig() {
        address2SymbolConfigMap.clear();
    }

    /**
     * Get the std model.
     * @param nameSpaceString the std name space string.
     * @return the std model.
     */
    public static CppStdModelBase getStdModel(String nameSpaceString) {
        String modelName;
        Matcher matcher = STL_MODEL_NAME_PATTERN.matcher(nameSpaceString);
        if (matcher.find()) {
            modelName = matcher.group(1);
            Logging.debug("Match \"" + nameSpaceString + "\" to model name: " + modelName);
        } else {
            return null;
        }
        return modelName == null ? null : symbol2StdModelMap.get(modelName);
    }

    /**
     * Reset all the containers in registered std models.
     */
    public static void resetStdContainers() {
        for (CppStdModelBase stdModel: symbol2StdModelMap.values()) {
            stdModel.resetPool();
        }
    }

    /**
     * Initialize all registered function models.
     */
    public static void initAll() {
        initSymbol2ExternalFunctionMap();
        initSymbol2StdModelMap();
    }
}
