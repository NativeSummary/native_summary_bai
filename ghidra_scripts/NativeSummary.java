//TODO write a description for this script
//@author
//@category _NativeSummary
//@keybinding
//@menupath
//@toolbar

import com.bai.env.funcs.FunctionModelManager;
import com.bai.util.*;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import org.example.nativesummary.mapping.JSONAnalyzer;
import org.example.nativesummary.util.EnvSetup;
import org.example.nativesummary.util.FuncCoverage;
import org.example.nativesummary.util.MyGlobalState;
import org.apache.commons.lang3.StringUtils;
import org.example.nativesummary.util.Statistics;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NativeSummary extends BinAbsInspector {
    public static final int TIMEOUT = 300;

    public void runOne(Function f, org.example.nativesummary.ir.Function irFunc, boolean fastMode) throws ContextChangeException {
        // TODO move reset after finished (currently for debug purpose)
        MyGlobalState.onStartOne(f, irFunc);
        GlobalState.reset();
        if (isRunningHeadless()) {
            String allArgString = StringUtils.join(getScriptArgs()).strip();
            GlobalState.config = Config.HeadlessParser.parseConfig(allArgString);
        } else {
            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.config.setGUI(true); // TODO change
            // change config here
            GlobalState.config.setEnableZ3(false);
        }
//        GlobalState.config.setDebug(true);
        GlobalState.config.clearCheckers();
        GlobalState.config.setEntryAddress("0x"+Long.toHexString(f.getEntryPoint().getOffset()));
        GlobalState.config.setCallStringK(1);
        if (fastMode) {
            GlobalState.config.setK(15);
            GlobalState.config.setTimeout(TIMEOUT);
        }

        if (!Logging.init()) {
            return;
        }
        FunctionModelManager.initAll();
        if (GlobalState.config.isEnableZ3() && !Utils.checkZ3Installation()) {
            return;
        }
        Logging.info("Preparing the program");
        if (!prepareProgram()) {
            Logging.error("Failed to prepare the program");
            return;
        }
        if (isRunningHeadless()) {
            if (!Utils.registerExternalFunctionsConfig(GlobalState.currentProgram, GlobalState.config)) {
                Logging.error("Failed to registerExternalFunctionsConfig, existing.");
                return;
            }
        } else {
//            Utils.loadCustomExternalFunctionFromLabelHistory(GlobalState.currentProgram);
        }
        GlobalState.arch = new Architecture(GlobalState.currentProgram);

        // !!ForDebug
        // GlobalState.config.setTimeout(5);


        // static code coverage
        Logging.info("Calculating static coverage"); long startTime = System.currentTimeMillis();
        MyGlobalState.funcCov.calcStaticCoverage(f, this);
        Logging.info("Calculating static coverage finished: " + MyGlobalState.funcCov.getStaticCoverage().size() + " block, " + (System.currentTimeMillis() - startTime) + "ms." );

        boolean success;
        try {
            success = analyze();
        } catch (CancelledException e) {
            success = false;
        }

        Logging.info("Calculating coverage"); startTime = System.currentTimeMillis();
        MyGlobalState.funcCov.calcCoverageStatstic();
        Logging.info("Calculating coverage finished: " + (System.currentTimeMillis() - startTime) + "ms.");
        Logging.info("Coverage Result: " + MyGlobalState.funcCov.getCoverageStatsticString());
        Logging.info("Collecting logs...");
        MyGlobalState.onFinishOne();
    }

    @Override
    public void run() throws Exception {
        long start = System.currentTimeMillis();
        // parse cmdline once
        Config conf = Config.HeadlessParser.parseConfig(StringUtils.join(getScriptArgs()).strip());
        if (conf.getNoOpt()) {
            println("Warning: disabling CalleeSavedReg optimization and local stack value passing optimization is only for experiment, and should not be enabled in most cases.");
        }
        if (conf.getNoModel()) {
            println("Warning: disabling function models is only for experiment, and should not be enabled in most cases.");
            FuncCoverage.isNoModel = true;
        }
        // only enable detailed info in noModel mode. (for experiment)
        Statistics stat = new Statistics(conf.getNoModel());
        stat.addStatistics(TIMEOUT, getCurrentProgram().getFunctionManager());
        println("Java home: "+System.getProperty("java.home"));
        MyGlobalState.reset(this);
        // setup external blocks
        new EnvSetup(getCurrentProgram(), this, getState(), this).run();

        // Apply func signature and return list of Function to analyze
        JSONAnalyzer a = new JSONAnalyzer(this, this, EnvSetup.getModuleDataTypeManager(this, "jni_all"));
        MyGlobalState.ja = a;
        String exe_path = getCurrentProgram().getExecutablePath();
        File binary = new File(exe_path);
        File jp = new File(exe_path + ".funcs.json");
        if (! jp.exists()) {
            exe_path = Paths.get(getProjectRootFolder().getProjectLocator().getLocation(), "..", binary.getName()).toString();
            jp = new File(exe_path + ".funcs.json");
        }
        JsonReader reader = new JsonReader(new FileReader(jp));
        JsonObject convertedObject = new Gson().fromJson(reader, JsonObject.class);
        // Function, tab separated key in json (String).
        List<Map.Entry<Function, org.example.nativesummary.ir.Function>> funcsToAnalyze = a.run(convertedObject);
        Set<Function> funcsSet = new HashSet<>(org.example.nativesummary.util.Utils.getListKeySet(funcsToAnalyze));
        // fire runOne on each function
        for(int i=0;i<funcsToAnalyze.size();i++) {
            Map.Entry<Function, org.example.nativesummary.ir.Function> e = funcsToAnalyze.get(i);
            println("Analyzing "+e.getKey().getName());
            long startOne = System.currentTimeMillis();
            try {
                // disable timeout if GUI mode(debug).
                runOne(e.getKey(), e.getValue(), isRunningHeadless());
            } catch (Exception exc) {
                Logging.error("Failed to analyze: "+e.getKey().getName()+", ("+e.getKey().getEntryPoint()+")");
                Logging.error(exc.getMessage());
                Logging.error(org.example.nativesummary.util.Utils.getExceptionStackTrace(exc));
                continue;
            }
            if (e.getKey().getName().equals("JNI_OnLoad")) {
                if (i != 0) {
                    Logging.error("JNI_OnLoad must be the first function in the list!");
                    return;
                }
                if (MyGlobalState.se.hasDynamicRegister()) {
                    Logging.info("Dynamic register behaviour in JNI_OnLoad");
                } else {
                    Logging.info("No Dynamic register behaviour in JNI_OnLoad");
                }
                funcsToAnalyze.addAll(org.example.nativesummary.util.Utils.dedupList(funcsSet, MyGlobalState.se.handleDynamicRegister()));
                MyGlobalState.onJNIOnLoadFinish();
            } else if (MyGlobalState.se.hasDynamicRegister()) {
                Logging.info("Dynamic register behaviour in func: "+e.getKey().getName());
                funcsToAnalyze.addAll(org.example.nativesummary.util.Utils.dedupList(funcsSet, MyGlobalState.se.handleDynamicRegister()));
            }
            long durationOne = System.currentTimeMillis() - startOne;
            println("Analysis spent "+durationOne+" ms for "+e.getKey().getName());
            if (getMonitor().isCancelled() || Thread.currentThread().isInterrupted()) {
                Logging.warn("Run Cancelled.");
                break;
                // if cancelled, not add current func to statistics
            }
            // add statistic info.
            stat.addJNI(e.getKey(), e.getValue(), durationOne, MyGlobalState.funcCov, MyGlobalState.isTaskTimeout);
            stat.write(exe_path + ".perf.json");
        }
        FileOutputStream fw = new FileOutputStream(exe_path + ".summary.java_serialize");
        FileWriter irFw = new FileWriter(exe_path + ".summary.ir.ll");
        MyGlobalState.se.export(fw, irFw, null);
        fw.close();
        irFw.close();
        long duration = System.currentTimeMillis() - start;
        if (getMonitor().isCancelled()) {
            println("Script execution cancelled by user.");
        }
        // write statistics.
        stat.addTotalScriptTime(duration);
        stat.write(exe_path + ".perf.json");
        println("NativeSummary script execution time: "+duration + "ms.");
    }
}
