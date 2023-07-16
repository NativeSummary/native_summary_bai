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
import org.example.nativesummary.util.Coverage;
import org.example.nativesummary.util.EnvSetup;
import org.example.nativesummary.util.MyGlobalState;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

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
                return;
            }
        } else {
//            Utils.loadCustomExternalFunctionFromLabelHistory(GlobalState.currentProgram);
        }
        GlobalState.arch = new Architecture(GlobalState.currentProgram);

        // !!ForDebug
        // GlobalState.config.setTimeout(5);

        // static code coverage
        Logging.info("Calculating static Coverage"); long startTime = System.currentTimeMillis();
        Coverage.calcStaticCoverage(MyGlobalState.staticCoverage, f, this, new HashSet<>());
        Logging.info("Calculating static Coverage finished: " +String.valueOf(MyGlobalState.staticCoverage.size()) + " block, " + String.valueOf((System.currentTimeMillis() - startTime)) + "ms." );

        boolean success;
        try {
            success = analyze();
        } catch (CancelledException e) {
            success = false;
        }

        Logging.info("Coverage Result: " + Coverage.getCoverageStatstic(MyGlobalState.staticCoverage, MyGlobalState.coverage));
        Logging.info("Collecting logs...");
        MyGlobalState.onFinishOne();
    }


    @Override
    public void run() throws Exception {
        // parse cmdline once
        if (Config.HeadlessParser.parseConfig(StringUtils.join(getScriptArgs()).strip()).getNoCalleeSavedReg()) {
            println("Warning: noCalleeSavedReg is only for experiment, should not be enabled in most cases.");
        }
        long start = System.currentTimeMillis();
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
        // fire runOne on each function
        for(int i=0;i<funcsToAnalyze.size();i++){
            Map.Entry<Function, org.example.nativesummary.ir.Function> e = funcsToAnalyze.get(i);
            println("Analyzing "+e.getKey().getName());
            long startOne = System.currentTimeMillis();
            // disable timeout if GUI mode(debug).
            runOne(e.getKey(), e.getValue(), isRunningHeadless());
            if (i==0 && e.getKey().getName().equals("JNI_OnLoad")) {
                funcsToAnalyze.addAll(MyGlobalState.se.handleDynamicRegister());
                MyGlobalState.onJNIOnLoadFinish();
            }
            long durationOne = System.currentTimeMillis() - startOne;
            println("Analysis spent "+durationOne+" ms for "+e.getKey().getName());
            if (getMonitor().isCancelled() || Thread.currentThread().isInterrupted()) {
                break;
            }
        }
        FileOutputStream fw = new FileOutputStream(exe_path + ".summary.java_serialize");
        FileWriter irFw = new FileWriter(exe_path + ".summary.ir.ll");
        MyGlobalState.se.export(fw, irFw, null); // TODO apk name ??
        fw.close();
        irFw.close();
        long duration = System.currentTimeMillis() - start;
        if (getMonitor().isCancelled()) {
            println("Script execution cancelled by user.");
        }
        println("NativeSummary script execution time: "+duration + "ms.");
    }
}
